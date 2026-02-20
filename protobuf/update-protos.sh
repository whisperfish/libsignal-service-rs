#!/bin/bash
set -euo pipefail

update_proto() {
	case "$1" in
	  Signal-Android)
	  	git_revision="b5c666a1f4f6802984b0c9096b4563c39a758d26"
		prefix="lib/libsignal-service/src/main/protowire/";;
	  Signal-Desktop)
	  	git_revision="1099803d2cc306e3b59f11ba111520205ba90325"
		prefix="protos/";;
	esac
	curl -LsOf https://raw.githubusercontent.com/signalapp/${1}/${git_revision}/${prefix}${2}
}

update_proto Signal-Android Groups.proto
update_proto Signal-Android Provisioning.proto
update_proto Signal-Android SignalService.proto
update_proto Signal-Android StickerResources.proto
update_proto Signal-Android WebSocketResources.proto

update_proto Signal-Desktop DeviceName.proto
