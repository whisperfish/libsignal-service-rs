#!/bin/bash
set -euo pipefail

update_proto() {
	case "$1" in
	  Signal-Android)
	  	git_revision="d88a862e0985cc2bbc463c5f504f5bb4e91ad4fc"
		prefix="libsignal-service/src/main/protowire/";;
	  Signal-Desktop)
	  	git_revision="3a772b05c3a2e5da754b538a6d91929deb1ef665"
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
