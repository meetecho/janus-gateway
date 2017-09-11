#!/bin/bash
#
# janus-combine.sh
# Combine multiple MJR recording files into one WeBM video file
# Author: Marnus van Niekerk - m@mjvn.net
# Dependencies:	ffmpeg with filter_comlex support
#
#	This is a raw first attempt.
#	For now it assumes the first video is the longest and the result is never longer than the first.
#	It also assumes that there are only files from one session on the target directory.
#

#set -x

# Check that  at least one argument is passed and that it is a directory
if [ $# -lt 1 -o ! -d "$1" ]
then
	echo "USAGE: $0 dir [output]" >&1
	exit 1
fi

# Change to target directory
DIR="$1"
cd $DIR

# Clean up any previous attempt
/bin/rm -f *.webm *.opus

# List of video files
FILES=`/bin/ls -1 *video.mjr | sort -t- -k5 | sed 's/-video.mjr//g'`
CNT=`echo $FILES | wc -w`

# Convert all video files to WebM and OPUS and combine
# Calculate time differences in the same loop
i=0
BASEts=0
dt="unknown"
DIFF=0
TMPFILE=`mktemp`
for FILE in $FILES
do
	janus-pp-rec $FILE-video.mjr $FILE-video.webm
	if [ $FILE-audio.mjr ]
	then
		janus-pp-rec $FILE-audio.mjr $FILE-audio.opus
		ffmpeg -i $FILE-audio.opus -i $FILE-video.webm -c:v copy -c:a opus -strict experimental $FILE-video-combined.webm
	else
		/bin/cp $FILE-video.webm $FILE-video-combined.webm
	fi
	ts=`echo $FILE | cut -f5 -d-`

	if [ $BASEts = 0 ]
	then
		BASEts=$ts
		tmp=`echo $BASEts | cut -c1-10`
		dt=`date -d @$tmp "+%Y%m%d%H%M%S"`
	fi

	DIFF=$(($ts-$BASEts))
	DIFFms=`echo "scale=0;$DIFF/1000" | bc`
	DIFFs=`echo "scale=4;$DIFF/1000000" | bc`

	# Save variables to temp file for execution later
	echo "FILE$i=$FILE-video-combined.webm" >> $TMPFILE
	echo "DIFF$i=$DIFF" >> $TMPFILE
	echo "DIFFs$i=$DIFFs" >> $TMPFILE
	echo "DIFFms$i=$DIFFms" >> $TMPFILE

	i=$(($i+1))
done

# Set variables saved to file during loop
source $TMPFILE; /bin/rm -f $TMPFILE

# Name of output file
if [ $# -gt 1 ]
then
	OUT="$2"
else
	OUT=`basename $DIR`.$dt.webm
fi


# Now construct a command to create the combined video
if [ $CNT -eq 2 ] # Only 2 videos
then
	ffmpeg -i $FILE0 -i $FILE1 -filter_complex \
       "[0]pad=2*iw:ih[l];[1]setpts=PTS-STARTPTS+$DIFFs1/TB[1v]; [l][1v]overlay=x=W/2[v]; \
        [1]adelay=$DIFFms1|$DIFFms1[1a]; \
        [0][1a]amix=inputs=2[a]" \
       -map "[v]" -map "[a]" $OUT
fi

if [ $CNT -eq 3 ] # 3 videos
then
	ffmpeg -i $FILE0 -i $FILE1 -i $FILE2 -filter_complex \
       "[0]pad=2*iw:2*ih[l];[1]setpts=PTS-STARTPTS+$DIFFs1/TB[1v]; [l][1v]overlay=x=W/2[a]; \
        [2]setpts=PTS-STARTPTS+$DIFFs2/TB[2v]; [a][2v]overlay=y=H/2[v]; \
        [1]adelay=$DIFFms1|$DIFFms1[1a]; [2]adelay=$DIFFms2|$DIFFms2[2a]; \
        [0][1a][2a]amix=inputs=3[a]" \
       -map "[v]" -map "[a]" $OUT
fi

if [ $CNT -gt 3 ] # More than 3, combine only the first 4
then
	ffmpeg -i $FILE0 -i $FILE1 -i $FILE2 -i $FILE3 -filter_complex \
       "[0]pad=2*iw:2*ih[l];[1]setpts=PTS-STARTPTS+$DIFFs1/TB[1v]; [l][1v]overlay=x=W/2[a]; \
        [2]setpts=PTS-STARTPTS+$DIFFs2/TB[2v]; [a][2v]overlay=y=H/2[b]; \
        [3]setpts=PTS-STARTPTS+$DIFFs3/TB[3v]; [b][3v]overlay=y=H/2:x=W/2[v]; \
        [1]adelay=$DIFFms1|$DIFFms1[1a]; [2]adelay=$DIFFms2|$DIFFms2[2a]; \
        [3]adelay=$DIFFms3|$DIFFms3[3a]; \n
        [0][1a][2a][3a]amix=inputs=4[a]" \
       -map "[v]" -map "[a]" $OUT
fi

# Clean up
/bin/mv $OUT $OUT.protect	#safety net in case name matched below
/bin/rm -f *combined.webm *video.webm *.opus
/bin/mv $OUT.protect $OUT
