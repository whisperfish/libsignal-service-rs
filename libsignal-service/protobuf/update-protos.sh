#!/bin/bash
set -euo pipefail

GIT_REVISION=${1:-7275b95b583b64144fc7f935144b0a17c45244e7}

update_proto() {
	case "$1" in
	  Signal-Android) prefix="libsignal/service/src/main/proto/";;
	  Signal-Desktop) prefix="protos/";;
	esac
	curl -sLOf https://raw.githubusercontent.com/signalapp/${1}/${GIT_REVISION}/${prefix}${2}
}

update_proto Signal-Android Groups.proto
update_proto Signal-Android Provisioning.proto
update_proto Signal-Android SignalService.proto
update_proto Signal-Android StickerResources.proto
update_proto Signal-Android WebSocketResources.proto

update_proto Signal-Desktop DeviceName.proto
update_proto Signal-Desktop UnidentifiedDelivery.proto