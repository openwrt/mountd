#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/hdreg.h>
#include <scsi/sg.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <glob.h>
#include <libgen.h>
#include <poll.h>
#include <syslog.h>

#include "include/log.h"
#include "include/list.h"
#include "include/sys.h"
#include "include/signal.h"
#include "include/timer.h"
#include "include/autofs.h"
#include "include/ucix.h"
#include "include/fs.h"
#include "include/mount.h"

int mount_new(char *path, char *dev);

static struct list_head mounts;

/**
 * enum status - status of mount entry
 *
 * @STATUS_UNMOUNTED: currently not mounted
 * @STATUS_MOUNTED: mounted & ready for usage
 * @STATUS_EXPIRED: mount expired & *temporary* unmounted
 * @STATUS_IGNORE: entry should be ignored and never mounted
 */
enum status {
	STATUS_UNMOUNTED = 0,
	STATUS_MOUNTED,
	STATUS_EXPIRED,
	STATUS_IGNORE,
};

struct mount {
	struct list_head list;
	char name[64];
	char dev[64];
	char serial[64];
	char vendor[64];
	char model[64];
	char rev[64];
	enum status status;
	char size[64];
	char sector_size[64];
	int fs;
};

static char *fs_names[] = {
	"",
	"",
	"mbr",
	"ext2",
	"ext3",
	"fat",
	"hfsplus",
	"",
	"ntfs",
	"",
	"exfat",
	"ext4",
	"hfsplusjournal"
};

#define MAX_MOUNTED		32
#define MAX_MOUNT_NAME	32

static char mounted[MAX_MOUNTED][3][MAX_MOUNT_NAME];
static int mounted_count = 0;
extern char uci_path[32];

static void mount_dump_uci_state(void)
{
	struct uci_context *ctx;
	struct list_head *p;
	char mountd[] = {"mountd"};
	char type[] = {"mountd_disc"};
	int mounted = 0;
	unsigned long long int size = 0;
	unlink("/var/state/mountd");
	ctx = ucix_init("mountd");
	uci_set_savedir(ctx, "/var/state/");
	ucix_add_option_int(ctx, mountd, mountd, "count", list_count(&mounts));
	list_for_each(p, &mounts)
	{
		struct mount *q = container_of(p, struct mount, list);
		char t[64];
		if(q->fs == EXTENDED)
			continue;
		ucix_add_section(ctx, mountd, q->serial, type);
		strcpy(t, q->dev);
		t[3] = '\0';
		ucix_add_option(ctx, mountd, q->serial, "disc", t);
		ucix_add_option(ctx, mountd, q->serial, "sector_size", q->sector_size);
		snprintf(t, 64, "part%dmounted", atoi(&q->dev[3]));
		ucix_add_option(ctx, mountd, q->serial, t, q->status == STATUS_MOUNTED ? "1" : "0");
		ucix_add_option(ctx, mountd, q->serial, "vendor", q->vendor);
		ucix_add_option(ctx, mountd, q->serial, "model", q->model);
		ucix_add_option(ctx, mountd, q->serial, "rev", q->rev);
		snprintf(t, 64, "size%d", atoi(&q->dev[3]));
		ucix_add_option(ctx, mountd, q->serial, t, q->size);
		if(q->fs > MBR && q->fs <= LASTFS)
		{
			snprintf(t, 64, "fs%d", atoi(&q->dev[3]));
			ucix_add_option(ctx, mountd, q->serial, t, fs_names[q->fs]);
		}
		if (q->status == STATUS_MOUNTED)
			mounted++;
		if ((q->status != STATUS_IGNORE) && q->size && q->sector_size)
			size = size + (((unsigned long long int)atoi(q->size)) * ((unsigned long long int)atoi(q->sector_size)));
	}
	ucix_add_option_int(ctx, mountd, mountd, "mounted", mounted);
	ucix_add_option_int(ctx, mountd, mountd, "total", size);
	system_printf("echo -n %llu > /tmp/run/mountd_size", size);
	ucix_save_state(ctx, "mountd");
	ucix_cleanup(ctx);
}

static struct mount* mount_find(char *name, char *dev)
{
	struct list_head *p;
	list_for_each(p, &mounts)
	{
		struct mount *q = container_of(p, struct mount, list);
		if(name)
			if(!strcmp(q->name, name))
				return q;
		if(dev)
			if(!strcmp(q->dev, dev))
				return q;
	}
	return 0;
}

static void mount_add_list(char *name, char *dev, char *serial,
	char *vendor, char *model, char *rev, int ignore, char *size, char *sector_size, int fs)
{
	struct mount *mount;
	char dev_path[64], dev_link[64], tmp[64];

	mount  = malloc(sizeof(struct mount));
	INIT_LIST_HEAD(&mount->list);
	strncpy(mount->vendor, vendor, 64);
	strncpy(mount->model, model, 64);
	strncpy(mount->rev, rev, 64);
	strncpy(mount->name, name, 64);
	strncpy(mount->dev, dev, 64);
	strncpy(mount->serial, serial, 64);
	strncpy(mount->size, size, 64);
	strncpy(mount->sector_size, sector_size, 64);
	mount->status = STATUS_UNMOUNTED;
	mount->fs = fs;
	list_add(&mount->list, &mounts);

	if (ignore) {
		mount->status = STATUS_IGNORE;
	} else {
		struct stat st;

		log_printf("new mount : %s -> %s (%s)\n", name, dev, fs_names[mount->fs]);

		snprintf(dev_link, sizeof(dev_link), "%s%s", uci_path, name);
		snprintf(dev_path, sizeof(dev_path), "%s%s", "/tmp/run/mountd/", dev);
		/* If link aleady exists - replace it */
		if (lstat(dev_link, &st) ==  0 && S_ISLNK(st.st_mode)) {
			snprintf(tmp, sizeof(tmp), "%s%s", uci_path, "tmp");
			symlink(dev_path, tmp);
			rename(tmp, dev_link);
		} else {
			symlink(dev_path, dev_link);
		}
		if (!mount_new("/tmp/run/mountd/", dev))
			system_printf("ACTION=add DEVICE=%s NAME=%s /sbin/hotplug-call mount", dev, name);
	}
}

static int mount_check_disc(char *disc)
{
	FILE *fp = fopen("/proc/mounts", "r");
	char tmp[256];
	int avail = -1;
	if(!fp)
	{
		log_printf("error reading /proc/mounts");
		return avail;
	}
	while((fgets(tmp, 256, fp) != NULL) && (avail == -1))
	{
		char *t;
		char tmp2[32];
		t = strstr(tmp, " ");
		if(t)
		{
			int l;
			*t = '\0';
			l = snprintf(tmp2, 31, "/dev/%s", disc);

			if(!strncmp(tmp, tmp2, l))
				avail = 0;
		}
	}
	fclose(fp);
	return avail;
}

static int mount_wait_for_disc(char *disc)
{
	int i = 10;
	while(i--)
	{
		int ret = mount_check_disc(disc);
		if(!ret)
			return ret;
		poll(0, 0, 100);
	}
	return -1;
}

int mount_new(char *path, char *dev)
{
	struct mount *mount;
	char tmp[256];
	int ret = 1;
	pid_t pid;
	mount = mount_find(0, dev);
	if(!mount)
	{
		log_printf("request for invalid path %s%s\n", path, dev);
		return -1;
	}
	if (mount->status == STATUS_IGNORE || mount->status == STATUS_MOUNTED || mount->fs == EXTENDED)
		return -1;
	snprintf(tmp, 256, "%s%s", path, mount->dev);
	log_printf("mounting %s\n", tmp);
	mkdir(tmp, 777);

	pid = autofs_safe_fork();
	if(!pid)
	{
		char *options, *fstype;
		if(mount->fs == EXFAT)
		{
			options = "rw,uid=1000,gid=1000";
			fstype = "exfat";
		}
		if(mount->fs == FAT)
		{
			options = "rw,uid=1000,gid=1000";
			fstype = "vfat";
		}
		if(mount->fs == EXT4)
		{
			options = "rw,defaults";
			fstype = "ext4";
		}
		if(mount->fs == EXT3)
		{
			options = "rw,defaults";
			fstype = "ext3";
		}
		if(mount->fs == EXT2)
		{
			options = "rw,defaults";
			fstype = "ext2";
		}
		if(mount->fs == HFSPLUS)
		{
			options = "rw,defaults,uid=1000,gid=1000";
			fstype = "hfsplus";
		}
		if(mount->fs == HFSPLUSJOURNAL)
		{
			options = "ro,defaults,uid=1000,gid=1000";
			fstype = "hfsplus";
		}
		if(mount->fs == NTFS)
		{
			options = "force";
			fstype = "ntfs-3g";
		}
		if(mount->fs > MBR && mount->fs <= LASTFS)
		{
			struct uci_context *ctx;
			char *uci_options, *uci_fstype;
			ctx = ucix_init("mountd");
			if(fs_names[mount->fs])
			{
				uci_options = ucix_get_option(ctx, "mountd", fs_names[mount->fs], "options");
				uci_fstype = ucix_get_option(ctx, "mountd", fs_names[mount->fs], "fstype");
				if(uci_options)
					options = uci_options;
				if(uci_fstype)
					fstype = uci_fstype;
				log_printf("mount -t %s -o %s /dev/%s %s", fstype, options, mount->dev, tmp);
				ret = system_printf("mount -t %s -o %s /dev/%s %s", fstype, options, mount->dev, tmp);
			}
			ucix_cleanup(ctx);
		}
		exit(WEXITSTATUS(ret));
	}
	pid = waitpid(pid, &ret, 0);
	ret = WEXITSTATUS(ret);
	log_printf("----------> mount ret = %d\n", ret);
	if (ret && ret != 0xff) {
		rmdir(tmp);
		return -1;
	}
	if(mount_wait_for_disc(mount->dev) == 0)
	{
		mount->status = STATUS_MOUNTED;
		mount_dump_uci_state();
	} else return -1;
	return 0;
}

int mount_remove(char *path, char *dev)
{
	struct mount *mount;
	char tmp[256];
	int ret;
	snprintf(tmp, 256, "%s%s", path, dev);
	log_printf("device %s has expired... unmounting %s\n", dev, tmp);
	ret = system_printf("/bin/umount %s", tmp);
	if(ret != 0)
		return 0;
	rmdir(tmp);
	mount = mount_find(0, dev);
	if(mount)
		mount->status = STATUS_EXPIRED;
	log_printf("finished unmounting\n");
	mount_dump_uci_state();
	return 0;
}

static int dir_sort(const struct dirent **a, const struct dirent **b)
{
	return 0;
}

static int dir_filter(const struct dirent *a)
{
	if(strstr(a->d_name, ":"))
		return 1;
	return 0;
}

static char* mount_get_serial(char *dev)
{
	static char tmp[64];
	static char tmp2[64];
	int disc;
	static struct hd_driveid hd;
	int i;
	static char *serial;
	static char disc_id[13];
	snprintf(tmp, 64, "/dev/%s", dev);
	disc = open(tmp, O_RDONLY);
	if(!disc)
	{
		log_printf("Trying to open unknown disc\n");
		return 0;
	}
	i = ioctl(disc, HDIO_GET_IDENTITY, &hd);
	close(disc);
	if(!i)
		serial = (char*)hd.serial_no;
	/* if we failed, it probably a usb storage device */
	/* there must be a better way for this */
	if(i)
	{
		struct dirent **namelist;
		int n = scandir("/sys/bus/scsi/devices/", &namelist, dir_filter, dir_sort);
		if(n > 0)
		{
			while(n--)
			{
				char *t = strstr(namelist[n]->d_name, ":");
				if(t)
				{
					int id;
					struct stat buf;
					char tmp3[strlen(namelist[n]->d_name) + strlen(dev) + 31];
					int ret;
					*t = 0;
					id = atoi(namelist[n]->d_name);
					*t = ':';

					sprintf(tmp3, "/sys/bus/scsi/devices/%s/block:%s/", namelist[n]->d_name, dev);
					ret = stat(tmp3, &buf);
					if(ret)
					{
						sprintf(tmp3, "/sys/bus/scsi/devices/%s/block/%s/", namelist[n]->d_name, dev);
						ret = stat(tmp3, &buf);
					}
					if(!ret)
					{
						FILE *fp;
						snprintf(tmp2, 64, "/proc/scsi/usb-storage/%d", id);
						fp = fopen(tmp2, "r");
						if(fp)
						{
							while(fgets(tmp2, 64, fp) != NULL)
							{
								serial = strstr(tmp2, "Serial Number:");
								if(serial)
								{
									serial += strlen("Serial Number: ");
									serial[strlen(serial) - 1] = '\0';
									i = 0;
									break;
								}
							}
							fclose(fp);
						}
					}
				}
				free(namelist[n]);
			}
			free(namelist);
		}
	}
	if(i)
	{
		log_printf("could not find a serial number for the device %s\n", dev);
	} else {
		/* serial string id is cheap, but makes the discs anonymous */
		unsigned char uniq[6];
		unsigned int *u = (unsigned int*) uniq;
		int l = strlen(serial);
		int i;
		memset(disc_id, 0, 13);
		memset(uniq, 0, 6);
		for(i = 0; i < l; i++)
		{
			uniq[i%6] += serial[i];
		}
		sprintf(disc_id, "%08X%02X%02X", *u, uniq[4], uniq[5]);
		//log_printf("Serial number - %s %s\n", serial, disc_id);
		return disc_id;
	}
	sprintf(disc_id, "000000000000");
	return disc_id;
}

static void mount_dev_add(char *dev)
{
	struct mount *mount = mount_find(0, dev);
	if(!mount)
	{
		char node[64];
		char name[64];
		int ignore = 0;
		char *s;
		char tmp[64];
		char tmp2[64];
		char *p;
		struct uci_context *ctx;
		char vendor[64];
		char model[64];
		char rev[64];
		char size[64];
		char sector_size[64];
		FILE *fp;
		int offset = 3;
		int fs;

		strcpy(name, dev);
		if (!strncmp(name, "mmcblk", 6))
			offset = 7;
		name[offset] = '\0';
		s = mount_get_serial(name);
		if(!s) {
			return;
		}
		if (!strncmp(name, "mmcblk", 6)) {
			snprintf(tmp, 64, "part%s", &dev[8]);
			snprintf(node, 64, "SD-P%s", &dev[8]);

		} else {
			snprintf(tmp, 64, "part%s", &dev[3]);
			snprintf(node, 64, "USB-%s", &dev[2]);
		}
		if(node[4] >= 'a' && node[4] <= 'z')
		{
			node[4] -= 'a';
			node[4] += 'A';
		}
		ctx = ucix_init("mountd");
		p = ucix_get_option(ctx, "mountd", s, tmp);
		ucix_cleanup(ctx);
		if(p)
		{
			if(strlen(p) == 1)
			{
				if(*p == '0')
					ignore = 1;
			} else {
				snprintf(node, 64, "%s", p);
			}
		}
		strcpy(name, dev);
		name[3] = '\0';
		snprintf(tmp, 64, "/sys/class/block/%s/device/model", name);
		fp = fopen(tmp, "r");
		if(!fp)
		{
			snprintf(tmp, 64, "/sys/block/%s/device/model", name);
			fp = fopen(tmp, "r");
		}
		if(!fp)
			snprintf(model, 64, "unknown");
		else {
			fgets(model, 64, fp);
			model[strlen(model) - 1] = '\0';;
			fclose(fp);
		}
		snprintf(tmp, 64, "/sys/class/block/%s/device/vendor", name);
		fp = fopen(tmp, "r");
		if(!fp)
		{
			snprintf(tmp, 64, "/sys/block/%s/device/vendor", name);
			fp = fopen(tmp, "r");
		}
		if(!fp)
			snprintf(vendor, 64, "unknown");
		else {
			fgets(vendor, 64, fp);
			vendor[strlen(vendor) - 1] = '\0';
			fclose(fp);
		}
		snprintf(tmp, 64, "/sys/class/block/%s/device/rev", name);
		fp = fopen(tmp, "r");
		if(!fp)
		{
			snprintf(tmp, 64, "/sys/block/%s/device/rev", name);
			fp = fopen(tmp, "r");
		}
		if(!fp)
			snprintf(rev, 64, "unknown");
		else {
			fgets(rev, 64, fp);
			rev[strlen(rev) - 1] = '\0';
			fclose(fp);
		}
		snprintf(tmp, 64, "/sys/class/block/%s/size", dev);
		fp = fopen(tmp, "r");
		if(!fp)
		{
			snprintf(tmp, 64, "/sys/block/%s/%s/size", name, dev);
			fp = fopen(tmp, "r");
		}
		if(!fp)
			snprintf(size, 64, "unknown");
		else {
			fgets(size, 64, fp);
			size[strlen(size) - 1] = '\0';
			fclose(fp);
		}
		strcpy(tmp2, dev);
		tmp2[3] = '\0';
		snprintf(tmp, 64, "/sys/block/%s/queue/hw_sector_size", tmp2);
		fp = fopen(tmp, "r");
		if(!fp)
			snprintf(sector_size, 64, "unknown");
		else {
			fgets(sector_size, 64, fp);
			sector_size[strlen(sector_size) - 1] = '\0';
			fclose(fp);
		}
		snprintf(tmp, 64, "/dev/%s", dev);
		fs = detect_fs(tmp);
		if (fs <= MBR || fs > LASTFS) {
			ignore = 1;
		}
		mount_add_list(node, dev, s, vendor, model, rev, ignore, size, sector_size, fs);
		mount_dump_uci_state();
	}
}

static int mount_dev_del(struct mount *mount)
{
	char tmp[256];
	int err = 0;

	if (mount->status == STATUS_MOUNTED) {
		snprintf(tmp, 256, "%s%s", "/tmp/run/mountd/", mount->dev);
		log_printf("device %s has disappeared ... unmounting %s\n", mount->dev, tmp);
		if (umount(tmp)) {
			err = -errno;
			umount2(tmp, MNT_DETACH);
		}
		rmdir(tmp);
		mount_dump_uci_state();
	}

	return err;
}

void mount_dump_list(void)
{
	struct list_head *p;
	list_for_each(p, &mounts)
	{
		struct mount *q = container_of(p, struct mount, list);
		log_printf("* %s %s %d\n", q->name, q->dev, q->status == STATUS_MOUNTED);
	}
}

char* is_mounted(char *block, char *path)
{
	int i;
	for(i = 0; i < mounted_count; i++)
	{
		if(block)
			if(!strncmp(&mounted[i][0][0], block, strlen(&mounted[i][0][0])))
				return &mounted[i][0][0];
		if(path)
			if(!strncmp(&mounted[i][1][1], &path[1], strlen(&mounted[i][1][0])))
				return &mounted[i][0][0];
	}
	return 0;
}

static void mount_update_mount_list(void)
{
	FILE *fp = fopen("/proc/mounts", "r");
	char tmp[256];

	if(!fp)
	{
		log_printf("error reading /proc/mounts");
		return;
	}
	mounted_count = 0;
	while(fgets(tmp, 256, fp) != NULL)
	{
		char *t, *t2;

		if (mounted_count + 1 > MAX_MOUNTED) {
			log_printf("found more than %d mounts \n", MAX_MOUNTED);
			break;
		}

		t = strstr(tmp, " ");
		if(t)
		{
			*t = '\0';
			t++;
		} else t = tmp;
		strncpy(&mounted[mounted_count][0][0], tmp, MAX_MOUNT_NAME);
		t2 = strstr(t, " ");
		if(t2)
		{
			*t2 = '\0';
			t2++;
		} else t2 = t;
		strncpy(&mounted[mounted_count][1][0], t, MAX_MOUNT_NAME);
		t = strstr(t2, " ");
		if(t)
		{
			*t = '\0';
			t++;
		} else t = tmp;
		strncpy(&mounted[mounted_count][2][0], t2, MAX_MOUNT_NAME);
	/*	printf("%s %s %s\n",
			mounted[mounted_count][0],
			mounted[mounted_count][1],
			mounted[mounted_count][2]);*/

		mounted_count++;
	}
	fclose(fp);
}

/* FIXME: we need more intelligence here */
static int dir_filter2(const struct dirent *a)
{
	if(!strncmp(a->d_name, "mmcblk", 6) || !strncmp(a->d_name, "sd", 2))
		return 1;
	return 0;
}
#define MAX_BLOCK	64
static char block[MAX_BLOCK][MAX_BLOCK];
static int blk_cnt = 0;

static int check_block(char *b)
{
	int i;
	for(i = 0; i < blk_cnt; i++)
	{
		if(!strcmp(block[i], b))
			return 1;
	}
	return 0;
}

static void mount_enum_drives(void)
{
	struct dirent **namelist, **namelist2;
	int i, n = scandir("/sys/block/", &namelist, dir_filter2, dir_sort);
	struct list_head *p;
	blk_cnt = 0;
	if(n > 0)
	{
		while(n--)
		{
			if(blk_cnt < MAX_BLOCK)
			{
				int m;
				char tmp[64];
				snprintf(tmp, 64, "/sys/block/%s/", namelist[n]->d_name);
				m = scandir(tmp, &namelist2, dir_filter2, dir_sort);
				if(m > 0)
				{
					while(m--)
					{
						strncpy(&block[blk_cnt][0], namelist2[m]->d_name, MAX_BLOCK);
						blk_cnt++;
						free(namelist2[m]);
					}
					free(namelist2);
				} else {
					strncpy(&block[blk_cnt][0], namelist[n]->d_name, MAX_BLOCK);
					blk_cnt++;
				}
			}
			free(namelist[n]);
		}
		free(namelist);
	}
	p = mounts.next;
	while(p != &mounts)
	{
		struct mount *q = container_of(p, struct mount, list);
		char tmp[64];
		struct uci_context *ctx;
		int del = 0;
		char *t;
		snprintf(tmp, 64, "part%s", &q->dev[3]);
		ctx = ucix_init("mountd");
		t = ucix_get_option(ctx, "mountd", q->serial, tmp);
		ucix_cleanup(ctx);
		if (t && q->status != STATUS_MOUNTED)
		{
			if(!strcmp(t, "0"))
			{
				if (q->status != STATUS_IGNORE)
					del = 1;
			} else if(!strcmp(t, "1"))
			{
				if(strncmp(q->name, "Disc-", 5))
					del = 1;
			} else if(strcmp(q->name, t))
			{
				del = 1;
			}
		}
		if(!check_block(q->dev)||del)
		{
			if (q->status == STATUS_MOUNTED || q->status == STATUS_EXPIRED) {
				char dev_link[64];
				int err;

				system_printf("ACTION=remove DEVICE=%s NAME=%s /sbin/hotplug-call mount", q->dev, q->name);

				err = mount_dev_del(q);

				snprintf(dev_link, sizeof(dev_link), "%s%s", uci_path, q->name);
				if (err == -EBUSY) {
					/* Create "tmp" symlink to non-existing path */
					snprintf(tmp, sizeof(tmp), "%s%s", uci_path, "tmp");
					symlink("## DEVICE MISSING ##", tmp);

					/* Replace old symlink with the not working one */
					rename(tmp, dev_link);
				} else {
					log_printf("unlinking %s\n", dev_link);
					unlink(dev_link);
				}
			}

			p->prev->next = p->next;
			p->next->prev = p->prev;
			p = p->next;
			free(q);

			mount_dump_uci_state();
			system_printf("/etc/fonstated/ReloadSamba");
		} else p = p->next;
	}

	for(i = 0; i < blk_cnt; i++)
		mount_dev_add(block[i]);
}

static void mount_check_enum(void)
{
	waitpid(-1, 0, WNOHANG);
	mount_enum_drives();
}

void mount_init(void)
{
	INIT_LIST_HEAD(&mounts);
	timer_add(mount_update_mount_list, 2);
	timer_add(mount_check_enum, 1);
	mount_update_mount_list();
}
