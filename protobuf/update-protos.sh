#!/bin/bash
set -euo pipefail

update_proto() {
	case "$1" in
	  Signal-Android)
	  	git_revision="77e678e05cfd2c643aede05ab0d8fad494b686a7"
		prefix="libsignal-service/src/main/protowire/";;
	  Signal-Desktop)
	  	git_revision="4c4aa84525d19e7566f55daadae9ef80b921ca20"
		prefix="protos/";;
	esac
	curl -LOf https://raw.githubusercontent.com/signalapp/${1}/${git_revision}/${prefix}${2}
}

update_proto Signal-Android Groups.proto
update_proto Signal-Android Provisioning.proto
update_proto Signal-Android SignalService.proto
update_proto Signal-Android StickerResources.proto
update_proto Signal-Android WebSocketResources.proto

update_proto Signal-Desktop DeviceName.proto
