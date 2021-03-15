ccflags-y += -I$(src)			# needed for trace events

obj-y					+= ion/

obj-$(CONFIG_ASHMEM)			+= ashmem.o
obj-$(CONFIG_ANDROID_TIMED_OUTPUT)	+= timed_output.o
obj-$(CONFIG_ANDROID_TIMED_GPIO)	+= timed_gpio.o
obj-$(CONFIG_ANDROID_LOW_MEMORY_KILLER)	+= lowmemorykiller.o
obj-$(CONFIG_SYNC)			+= sync.o
ifdef CONFIG_DEBUG_FS
obj-$(CONFIG_SYNC)			+= sync_debug.o
endif
obj-$(CONFIG_SW_SYNC)			+= sw_sync.o
obj-$(CONFIG_ONESHOT_SYNC)		+= oneshot_sync.o
lmk_tng-y := lowmemorykiller_tng.o lowmemorykiller_tasks.o \
             lowmemorykiller_oom.o lowmemorykiller_vmpressure.o
obj-$(CONFIG_ANDROID_LOW_MEMORY_KILLER_TNG) += lmk_tng.o
obj-$(CONFIG_ANDROID_LOW_MEMORY_KILLER_STATS) += lowmemorykiller_stats.o
obj-$(CONFIG_ANDROID_VSOC)		+= vsoc.o
