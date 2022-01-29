#! /bin/bash

# Script For Building Android arm64 Kernel
#
# Copyright (c) 2018-2020 Panchajanya1999 <rsk52959@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Kernel building script

# Function to show an informational message
msg() {
    echo -e "\e[1;32m$*\e[0m"
}

err() {
    echo -e "\e[1;41m$*\e[0m"
    exit 1
}

##------------------------------------------------------##
##----------Basic Informations, COMPULSORY--------------##

# The defult directory where the kernel should be placed
KERNEL_DIR=$PWD

# The name of the Kernel, to name the ZIP
KERNEL="STRIX"

# Kernel zip name type
TYPE="nightly"

# The name of the device for which the kernel is built
MODEL="Redmi Note 6 Pro"
MODEL1="Redmi Note 5 Pro"

# The codename of the device
DEVICE="tulip"
DEVICE1="whyred"

# Retrieves branch information
CI_BRANCH=$(git rev-parse --abbrev-ref HEAD)
export CI_BRANCH

# Kernel revision
KERNELTYPE=EAS
KERNELTYPE1=HMP

# The defconfig which should be used. Get it from config.gz from
# your device or check source
DEFCONFIG=tulip_defconfig
DEFCONFIG1=whyred_defconfig

# Show manufacturer info
MANUFACTURERINFO="XiaoMI, Inc."

# Specify compiler. 
# 'clang' or 'gcc'
if [[ "$CI_BRANCH" == "sdm660-hmp-rebase" ]]; then
	COMPILER=gcc
elif [[ "$CI_BRANCH" == "lto-gcc-clang" ]]; then
	COMPILER=clang
else
	COMPILER=gcc
fi

	if [ $COMPILER = "clang" ]
	then
		# install few necessary packages
		apt-get update -y && apt-get -y install llvm lld
	else
		apt-get -y install libfl-dev
	fi

# Clean source prior building. 1 is NO(default) | 0 is YES
INCREMENTAL=1

# Push ZIP to Telegram. 1 is YES | 0 is NO(default)
PTTG=1
	if [ $PTTG = 1 ]
	then
		# Set Telegram Chat ID
		CHATID="-1001353688353"
	fi

# Generate a full DEFCONFIG prior building. 1 is YES | 0 is NO(default)
DEF_REG=0

# Build dtbo.img (select this only if your source has support to building dtbo.img)
# 1 is YES | 0 is NO(default)
BUILD_DTBO=0

# Sign the zipfile
# 1 is YES | 0 is NO
SIGN=0

# Debug purpose. Send logs on every successfull builds
# 1 is YES | 0 is NO(default)
LOG_DEBUG=0

##------------------------------------------------------##
##---------Do Not Touch Anything Beyond This------------##

# Check if we are using a dedicated CI ( Continuous Integration ), and
# set KBUILD_BUILD_VERSION and KBUILD_BUILD_HOST and CI_BRANCH

## Set defaults first
DISTRO=$(cat /etc/issue)
export token=$TELEGRAM_TOKEN

## Check for CI
if [ -n "$CI" ]
then
	if [ -n "$CIRCLECI" ]
	then
		export KBUILD_BUILD_VERSION=$CIRCLE_BUILD_NUM
		export KBUILD_BUILD_HOST="CircleCI"
		export CI_BRANCH=$CIRCLE_BRANCH
	fi
	if [ -n "$DRONE" ]
	then
		export KBUILD_BUILD_VERSION="1"
		export KBUILD_BUILD_HOST="DroneCI"
		export CI_BRANCH=$DRONE_BRANCH
	else
		echo "Not presetting Build Version"
	fi
fi

#Check Kernel Version
KERVER=$(make kernelversion)


# Set a commit head
COMMIT_HEAD=$(git log --oneline -1)

# Set Date 
DATE=$(TZ=Asia/Jakarta date +"%Y%m%d-%T")

#Now Its time for other stuffs like cloning, exporting, etc

 clone() {
	echo " "
	if [ $COMPILER = "clang" ]
	then
		if [[ "$CI_BRANCH" == "lto-gcc-clang" ]]; then
			msg "|| Cloning Proton clang ||"
			git clone --depth=1 https://github.com/kdrag0n/proton-clang.git clang
		else
			msg "|| Cloning STRIX clang ||"
			git clone --depth=1 https://github.com/STRIX-Project/STRIX-clang.git clang
		fi

		# Toolchain Directory defaults to clang-llvm
		TC_DIR=$KERNEL_DIR/clang
	elif [ $COMPILER = "gcc" ]
	then
		if [[ "$CI_BRANCH" == "sdm660-hmp-rebase" ]]; then
			msg "|| Cloning GCC 8 & 5 ||"
			git clone https://github.com/najahiiii/aarch64-linux-gnu.git -b gcc8-201903-A --depth=1 gcc64
			git clone https://github.com/arter97/arm-eabi-5.1.git -b master --depth=1 gcc32
			GCC64_DIR=$KERNEL_DIR/gcc64
			GCC32_DIR=$KERNEL_DIR/gcc32
		else
			msg "|| Cloning GCC 10.3.1 ||"
			git clone https://github.com/fiqri19102002/aarch64-gcc.git -b elf-gcc-11-tarballs --depth=1 gcc64
			git clone https://github.com/fiqri19102002/arm-gcc.git -b elf-gcc-11-tarballs --depth=1 gcc32
			GCC64_DIR=$KERNEL_DIR/gcc64
			GCC32_DIR=$KERNEL_DIR/gcc32
		fi
	fi

	msg "|| Cloning Anykernel ||"
	git clone --depth 1 https://github.com/STRIX-Project/AnyKernel3.git -b tulip-test

	if [ $BUILD_DTBO = 1 ]
	then
		msg "|| Cloning libufdt ||"
		git clone https://android.googlesource.com/platform/system/libufdt "$KERNEL_DIR"/scripts/ufdt/libufdt
	fi
}

##------------------------------------------------------##

exports() {
	export KBUILD_BUILD_USER="FiqriArdyansyah"
	export ARCH=arm64
	export SUBARCH=arm64

	if [ $COMPILER = "clang" ]
	then
		KBUILD_COMPILER_STRING=$("$TC_DIR"/bin/clang --version | head -n 1 | perl -pe 's/\(http.*?\)//gs' | sed -e 's/  */ /g' -e 's/[[:space:]]*$//')
		PATH=$TC_DIR/bin/:$PATH
	elif [ $COMPILER = "gcc" ]
	then
		if [[ "$CI_BRANCH" == "sdm660-hmp-rebase" ]]; then
			KBUILD_COMPILER_STRING="gcc version 8.3.0(GNU Toolchain for the A-profile Architecture 8.3-2019.03(arm-rel-8.36))"
			PATH=$GCC64_DIR/bin/:$GCC32_DIR/bin/:/usr/bin:$PATH
		else
			KBUILD_COMPILER_STRING=$("$GCC64_DIR"/bin/aarch64-elf-gcc --version | head -n 1)
			PATH=$GCC64_DIR/bin/:$GCC32_DIR/bin/:/usr/bin:$PATH
		fi
	fi

	export PATH KBUILD_COMPILER_STRING
	export BOT_MSG_URL="https://api.telegram.org/bot$token/sendMessage"
	export BOT_BUILD_URL="https://api.telegram.org/bot$token/sendDocument"
	PROCS=$(nproc --all)
	export PROCS
}

##---------------------------------------------------------##

tg_post_msg() {
	curl -s -X POST "$BOT_MSG_URL" -d chat_id="$2" \
	-d "disable_web_page_preview=true" \
	-d "parse_mode=html" \
	-d text="$1"

}

##----------------------------------------------------------------##

tg_post_build() {
	#Post MD5Checksum alongwith for easeness
	MD5CHECK=$(md5sum "$1" | cut -d' ' -f1)

	#Show the Checksum alongwith caption
	curl --progress-bar -F document=@"$1" "$BOT_BUILD_URL" \
	-F chat_id="$2"  \
	-F "disable_web_page_preview=true" \
	-F "parse_mode=html" \
	-F caption="$3 | <b>MD5 Checksum : </b><code>$MD5CHECK</code>"  
}

##----------------------------------------------------------##

# Set naming to old cam for zip file
setversioning() {
if [[ "$CI_BRANCH" == "sdm660-oc-test" ]]; then
	KERNELNAME="$KERNEL-$DEVICE-$KERNELTYPE-OC-$TYPE-oldcam-$DATE"
	export KERNELTYPE KERNELNAME
	export ZIPNAME="$KERNELNAME.zip"
elif [[ "$CI_BRANCH" == "sdm660-eas-test" ]]; then
	KERNELNAME="$KERNEL-$DEVICE-$KERNELTYPE-$TYPE-oldcam-$DATE"
	export KERNELTYPE KERNELNAME
	export ZIPNAME="$KERNELNAME.zip"
elif [[ "$CI_BRANCH" == "sdm660-hmp-rebase" ]]; then
	KERNELNAME="$KERNEL-$DEVICE-$KERNELTYPE1-$TYPE-oldcam-$DATE"
	export KERNELTYPE KERNELNAME
	export ZIPNAME="$KERNELNAME.zip"
else
	KERNELNAME="$KERNEL-$DEVICE-$KERNELTYPE-$TYPE-oldcam-$DATE"
	export KERNELTYPE KERNELNAME
	export ZIPNAME="$KERNELNAME.zip"
fi
}

##--------------------------------------------------------------##

build_kernel() {
	if [ $INCREMENTAL = 0 ]
	then
		msg "|| Cleaning Sources ||"
		make clean && make mrproper && rm -rf out
	fi

	if [ "$PTTG" = 1 ]
 	then
		tg_post_msg "<b>Docker OS: </b><code>$DISTRO</code>%0A<b>Kernel Version : </b><code>$KERVER</code>%0A<b>Date : </b><code>$(TZ=Asia/Jakarta date)</code>%0A<b>Device : </b><code>$MODEL [$DEVICE]</code>%0A<b>Manufacturer : </b><code>$MANUFACTURERINFO</code>%0A<b>Pipeline Host : </b><code>$KBUILD_BUILD_HOST</code>%0A<b>Host Core Count : </b><code>$PROCS</code>%0A<b>Compiler Used : </b><code>$KBUILD_COMPILER_STRING</code>%0a<b>Branch : </b><code>$CI_BRANCH</code>%0A<b>Top Commit : </b><code>$COMMIT_HEAD</code>%0A<b>Status : </b>#Nightly" "$CHATID"
	fi

	msg "|| Started Compilation ||"

	make O=out $DEFCONFIG
	if [ $DEF_REG = 1 ]
	then
		cp .config arch/arm64/configs/$DEFCONFIG
		git add arch/arm64/configs/$DEFCONFIG
		git commit -m "$DEFCONFIG: Regenerate

						This is an auto-generated commit"
	fi

	BUILD_START=$(date +"%s")
	
	if [ $COMPILER = "clang" ]
	then
		make -j"$PROCS" O=out \
				CROSS_COMPILE=aarch64-linux-gnu- \
				CROSS_COMPILE_ARM32=arm-linux-gnueabi- \
				CC=clang \
				AR=llvm-ar \
				NM=llvm-nm \
				LD=ld.lld \
				OBJDUMP=llvm-objdump \
				STRIP=llvm-strip
	fi

	if [ $COMPILER = "gcc" ]
	then
		if [[ "$CI_BRANCH" == "sdm660-hmp-rebase" ]]; then
			export CROSS_COMPILE_ARM32=$GCC32_DIR/bin/arm-eabi-
			make -j"$PROCS" O=out CROSS_COMPILE=aarch64-linux-gnu-
		else
			export CROSS_COMPILE_ARM32=$GCC32_DIR/bin/arm-eabi-
			make -j"$PROCS" O=out CROSS_COMPILE=aarch64-elf-
		fi
	fi

	BUILD_END=$(date +"%s")
	DIFF=$((BUILD_END - BUILD_START))

	if [ -f "$KERNEL_DIR"/out/arch/arm64/boot/Image.gz-dtb ] 
	then
		msg "|| Kernel successfully compiled ||"
	elif ! [ -f $KERNEL_DIR/out/arch/arm64/boot/Image.gz-dtb ]
	then
		echo -e "Kernel compilation failed, See buildlog to fix errors"
		tg_post_msg "<b>Build failed to compile after $((DIFF / 60)) minute(s) and $((DIFF % 60)) seconds</b>" "$CHATID"
		exit 1
	fi

	if [ $BUILD_DTBO = 1 ]
	then
		msg "|| Building DTBO ||"
		tg_post_msg "<code>Building DTBO..</code>" "$CHATID"
		python2 "$KERNEL_DIR/scripts/ufdt/libufdt/utils/src/mkdtboimg.py" \
			create "$KERNEL_DIR/out/arch/arm64/boot/dtbo.img" --page_size=4096 "$KERNEL_DIR/out/arch/arm64/boot/dts/qcom/sm6150-idp-overlay.dtbo"
	fi
}

##--------------------------------------------------------------##

gen_zip() {
	msg "|| Zipping into a flashable zip ||"
	mv "$KERNEL_DIR"/out/arch/arm64/boot/Image.gz-dtb AnyKernel3/Image.gz-dtb
	if [ $BUILD_DTBO = 1 ]
	then
		mv "$KERNEL_DIR"/out/arch/arm64/boot/dtbo.img AnyKernel3/dtbo.img
	fi
	cd AnyKernel3 || exit
	zip -r9 "$ZIPNAME" * -x .git README.md

	## Prepare a final zip variable
	ZIP_FINAL="$ZIPNAME"

	if [ "$PTTG" = 1 ]
 	then
		tg_post_build "$ZIP_FINAL" "$CHATID" "Build took : $((DIFF / 60)) minute(s) and $((DIFF % 60)) second(s)"
	fi
	cd ..
}

##--------------------------------------------------------------##

# Now Its time for other stuffs like cloning
cloneak() {
	rm -rf "$KERNEL_DIR/AnyKernel3"
	msg "|| Cloning Anykernel for tulip ||"
	git clone --depth 1 https://github.com/STRIX-Project/AnyKernel3.git -b tulip
}

# Ship China firmware builds
setnewcam() {
    # Switch to new cam blob from defconfig
    sed -i 's/CONFIG_MACH_XIAOMI_NEW_CAMERA=n/CONFIG_MACH_XIAOMI_NEW_CAMERA=y/g' arch/arm64/configs/$DEFCONFIG
    msg "|| Newcam for tulip ready ||"
}

# Set naming to new cam for zip file
setversioning1() {
if [[ "$CI_BRANCH" == "sdm660-oc-test" ]]; then
	KERNELNAME1="$KERNEL-$DEVICE-$KERNELTYPE-OC-$TYPE-newcam-$DATE"
	export KERNELTYPE KERNELNAME1
	export ZIPNAME1="$KERNELNAME1.zip"
elif [[ "$CI_BRANCH" == "sdm660-eas-test" ]]; then
	KERNELNAME1="$KERNEL-$DEVICE-$KERNELTYPE-$TYPE-newcam-$DATE"
	export KERNELTYPE KERNELNAME1
	export ZIPNAME1="$KERNELNAME1.zip"
elif [[ "$CI_BRANCH" == "sdm660-hmp-rebase" ]]; then
	KERNELNAME1="$KERNEL-$DEVICE-$KERNELTYPE1-$TYPE-newcam-$DATE"
	export KERNELTYPE KERNELNAME1
	export ZIPNAME1="$KERNELNAME1.zip"
else
	KERNELNAME1="$KERNEL-$DEVICE-$KERNELTYPE-$TYPE-newcam-$DATE"
	export KERNELTYPE KERNELNAME1
	export ZIPNAME1="$KERNELNAME1.zip"
fi
}

gen_zip1() {
	msg "|| Zipping into a flashable zip ||"
	mv "$KERNEL_DIR"/out/arch/arm64/boot/Image.gz-dtb AnyKernel3/Image.gz-dtb
	if [ $BUILD_DTBO = 1 ]
	then
		mv "$KERNEL_DIR"/out/arch/arm64/boot/dtbo.img AnyKernel3/dtbo.img
	fi
	cd AnyKernel3 || exit
	zip -r9 "$ZIPNAME1" * -x .git README.md

	## Prepare a final zip variable
	ZIP_FINAL="$ZIPNAME1"

	if [ "$PTTG" = 1 ]
 	then
		tg_post_build "$ZIP_FINAL" "$CHATID" "Build took : $((DIFF / 60)) minute(s) and $((DIFF % 60)) second(s)"
	fi
	cd ..
}

if [[ "$CI_BRANCH" == "sdm660-hmp-rebase" ]]; then
	setversioning
	clone
	exports
	build_kernel
	gen_zip
else
	setversioning
	clone
	exports
	build_kernel
	gen_zip
	setversioning1
	setnewcam
	cloneak
	build_kernel
	gen_zip1
fi

if [ $LOG_DEBUG = "1" ]
then
	tg_post_build "error.log" "$CHATID" "Debug Mode Logs"
fi

##------------------------------------------------------------------##

msg "|| compile for whyred device ||"

rm -r "$KERNEL_DIR/out"
mkdir "$KERNEL_DIR/out"

##----------------------------------------------------------##

# Now Its time for other stuffs like cloning
cloneak1() {
	rm -rf "$KERNEL_DIR/AnyKernel3"
	msg "|| Cloning Anykernel for whyred ||"
	git clone --depth 1 https://github.com/STRIX-Project/AnyKernel3.git -b whyred-test
}

##------------------------------------------------------------------##

build_kernel1() {
	if [ $INCREMENTAL = 0 ]
	then
		msg "|| Cleaning Sources ||"
		make clean && make mrproper && rm -rf out
	fi

	if [ "$PTTG" = 1 ]
 	then
		tg_post_msg "<b>Docker OS: </b><code>$DISTRO</code>%0A<b>Kernel Version : </b><code>$KERVER</code>%0A<b>Date : </b><code>$(TZ=Asia/Jakarta date)</code>%0A<b>Device : </b><code>$MODEL1 [$DEVICE1]</code>%0A<b>Manufacturer : </b><code>$MANUFACTURERINFO</code>%0A<b>Pipeline Host : </b><code>$KBUILD_BUILD_HOST</code>%0A<b>Host Core Count : </b><code>$PROCS</code>%0A<b>Compiler Used : </b><code>$KBUILD_COMPILER_STRING</code>%0a<b>Branch : </b><code>$CI_BRANCH</code>%0A<b>Last Commit : </b><code>$COMMIT_HEAD</code>%0A<b>Status : </b>#Nightly" "$CHATID"
	fi

	msg "|| Started Compilation ||"

	make O=out $DEFCONFIG1
	if [ $DEF_REG = 1 ]
	then
		cp .config arch/arm64/configs/$DEFCONFIG1
		git add arch/arm64/configs/$DEFCONFIG1
		git commit -m "$DEFCONFIG1: Regenerate

						This is an auto-generated commit"
	fi

	BUILD_START=$(date +"%s")
	
	if [ $COMPILER = "clang" ]
	then
		make -j"$PROCS" O=out \
				CROSS_COMPILE=aarch64-linux-gnu- \
				CROSS_COMPILE_ARM32=arm-linux-gnueabi- \
				CC=clang \
				AR=llvm-ar \
				OBJDUMP=llvm-objdump \
				STRIP=llvm-strip
	fi

	if [ $COMPILER = "gcc" ]
	then
		if [[ "$CI_BRANCH" == "sdm660-hmp-rebase" ]]; then
			export CROSS_COMPILE_ARM32=$GCC32_DIR/bin/arm-eabi-
			make -j"$PROCS" O=out CROSS_COMPILE=aarch64-linux-gnu-
		else
			export CROSS_COMPILE_ARM32=$GCC32_DIR/bin/arm-eabi-
			make -j"$PROCS" O=out CROSS_COMPILE=aarch64-elf-
		fi
	fi

	BUILD_END=$(date +"%s")
	DIFF=$((BUILD_END - BUILD_START))

	if [ -f "$KERNEL_DIR"/out/arch/arm64/boot/Image.gz-dtb ] 
	then
		msg "|| Kernel successfully compiled ||"
	elif ! [ -f $KERNEL_DIR/out/arch/arm64/boot/Image.gz-dtb ]
	then
		echo -e "Kernel compilation failed, See buildlog to fix errors"
		tg_post_msg "<b>Build failed to compile after $((DIFF / 60)) minute(s) and $((DIFF % 60)) seconds</b>" "$CHATID"
		exit 1
	fi

	if [ $BUILD_DTBO = 1 ]
	then
		msg "|| Building DTBO ||"
		tg_post_msg "<code>Building DTBO..</code>" "$CHATID"
		python2 "$KERNEL_DIR/scripts/ufdt/libufdt/utils/src/mkdtboimg.py" \
			create "$KERNEL_DIR/out/arch/arm64/boot/dtbo.img" --page_size=4096 "$KERNEL_DIR/out/arch/arm64/boot/dts/qcom/sm6150-idp-overlay.dtbo"
	fi
}

##--------------------------------------------------------------##

# Set naming to old cam for zip file
setversioning2() {
if [[ "$CI_BRANCH" == "sdm660-oc-test" ]]; then
	KERNELNAME2="$KERNEL-$DEVICE1-$KERNELTYPE-OC-$TYPE-oldcam-$DATE"
	export KERNELTYPE KERNELNAME2
	export ZIPNAME2="$KERNELNAME2.zip"
elif [[ "$CI_BRANCH" == "sdm660-eas-test" ]]; then
	KERNELNAME2="$KERNEL-$DEVICE1-$KERNELTYPE-$TYPE-oldcam-$DATE"
	export KERNELTYPE KERNELNAME2
	export ZIPNAME2="$KERNELNAME2.zip"
elif [[ "$CI_BRANCH" == "sdm660-hmp-rebase" ]]; then
	KERNELNAME2="$KERNEL-$DEVICE1-$KERNELTYPE1-$TYPE-oldcam-$DATE"
	export KERNELTYPE KERNELNAME2
	export ZIPNAME2="$KERNELNAME2.zip"
else
	KERNELNAME2="$KERNEL-$DEVICE1-$KERNELTYPE-$TYPE-oldcam-$DATE"
	export KERNELTYPE KERNELNAME2
	export ZIPNAME2="$KERNELNAME2.zip"
fi
}

##--------------------------------------------------------------##

gen_zip2() {
	msg "|| Zipping into a flashable zip ||"
	mv "$KERNEL_DIR"/out/arch/arm64/boot/Image.gz-dtb AnyKernel3/Image.gz-dtb
	if [ $BUILD_DTBO = 1 ]
	then
		mv "$KERNEL_DIR"/out/arch/arm64/boot/dtbo.img AnyKernel3/dtbo.img
	fi
	cd AnyKernel3 || exit
	zip -r9 "$ZIPNAME2" * -x .git README.md

	# Prepare a final zip variable
	ZIP_FINAL="$ZIPNAME2"

	if [ "$PTTG" = 1 ]
 	then
		tg_post_build "$ZIP_FINAL" "$CHATID" "Build took : $((DIFF / 60)) minute(s) and $((DIFF % 60)) second(s)"
	fi
	cd ..
}

##--------------------------------------------------------------##

# Ship China firmware builds
setnewcam1() {
    # Switch to new cam from defconfig
    sed -i 's/CONFIG_MACH_XIAOMI_NEW_CAMERA=n/CONFIG_MACH_XIAOMI_NEW_CAMERA=y/g' arch/arm64/configs/$DEFCONFIG1
    msg "|| Newcam for whyred ready ||"
}

# Set naming to new cam for zip file
setversioning3() {
if [[ "$CI_BRANCH" == "sdm660-oc-test" ]]; then
    KERNELNAME3="$KERNEL-$DEVICE1-$KERNELTYPE-OC-$TYPE-newcam-$DATE"
	export KERNELTYPE KERNELNAME3
	export ZIPNAME3="$KERNELNAME3.zip"
elif [[ "$CI_BRANCH" == "sdm660-eas-test" ]]; then
	KERNELNAME3="$KERNEL-$DEVICE1-$KERNELTYPE-$TYPE-newcam-$DATE"
	export KERNELTYPE KERNELNAME3
	export ZIPNAME3="$KERNELNAME3.zip"
elif [[ "$CI_BRANCH" == "sdm660-hmp-rebase" ]]; then
	KERNELNAME3="$KERNEL-$DEVICE1-$KERNELTYPE1-$TYPE-newcam-$DATE"
	export KERNELTYPE KERNELNAME3
	export ZIPNAME3="$KERNELNAME3.zip"
else
	KERNELNAME3="$KERNEL-$DEVICE1-$KERNELTYPE-$TYPE-newcam-$DATE"
	export KERNELTYPE KERNELNAME3
	export ZIPNAME3="$KERNELNAME3.zip"
fi
}

gen_zip3() {
	msg "|| Zipping into a flashable zip ||"
	mv "$KERNEL_DIR"/out/arch/arm64/boot/Image.gz-dtb AnyKernel3/Image.gz-dtb
	if [ $BUILD_DTBO = 1 ]
	then
		mv "$KERNEL_DIR"/out/arch/arm64/boot/dtbo.img AnyKernel3/dtbo.img
	fi
	cd AnyKernel3 || exit
	zip -r9 "$ZIPNAME3" * -x .git README.md

	## Prepare a final zip variable
	ZIP_FINAL="$ZIPNAME3"

	if [ "$PTTG" = 1 ]
 	then
		tg_post_build "$ZIP_FINAL" "$CHATID" "Build took : $((DIFF / 60)) minute(s) and $((DIFF % 60)) second(s)"
	fi
	cd ..
}

if [[ "$CI_BRANCH" == "sdm660-hmp-rebase" ]]; then
	setversioning2
	cloneak1
	exports
	build_kernel1
	gen_zip2
else
	setversioning2
	cloneak1
	exports
	build_kernel1
	gen_zip2
	setversioning3
	setnewcam1
	cloneak1
	build_kernel1
	gen_zip3
fi

if [ $LOG_DEBUG = "1" ]
then
	tg_post_build "error.log" "$CHATID" "Debug Mode Logs"
fi
