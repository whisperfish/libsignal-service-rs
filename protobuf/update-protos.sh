#!/bin/bash
set -euo pipefail

update_proto() {
	case "$1" in
	  Signal-Android)
	  	git_revision="v8.15.0"
        ;;
	  Signal-Desktop)
	  	git_revision="v8.14.0"
        ;;
	esac
	curl -LsOf https://raw.githubusercontent.com/signalapp/${1}/${git_revision}/${2}
}

update_proto Signal-Android lib/libsignal-service/src/main/protowire/Groups.proto
update_proto Signal-Android lib/libsignal-service/src/main/protowire/Provisioning.proto
update_proto Signal-Android lib/libsignal-service/src/main/protowire/SignalService.proto
update_proto Signal-Android lib/libsignal-service/src/main/protowire/StickerResources.proto
update_proto Signal-Android lib/libsignal-service/src/main/protowire/StorageService.proto
update_proto Signal-Android core/network/src/main/protowire/WebSocketResources.proto

update_proto Signal-Desktop protos/DeviceName.proto
