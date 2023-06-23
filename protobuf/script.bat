protoc --proto_path=.\proto  --go_out=.\generated --go_opt=Mgoogle/protobuf/descriptor.proto=google/protobuf/descriptor.proto  --go_opt=Msteammessages_base.proto=proto/steammessages_base.proto  steammessages_base.proto

protoc --proto_path=.\proto  --go_out=.\generated --go_opt=Mgoogle/protobuf/descriptor.proto=google/protobuf/descriptor.proto  --go_opt=Msteammessages_base.proto=proto/steammessages_base.proto --go_opt=Msteammessages_unified_base.steamclient.proto=proto/steammessages_unified_base.steamclient.proto  steammessages_unified_base.steamclient.proto

protoc --proto_path=.\proto  --go_out=.\generated --go_opt=Mgoogle/protobuf/descriptor.proto=google/protobuf/descriptor.proto  --go_opt=Msteammessages_base.proto=proto/steammessages_base.proto --go_opt=Msteammessages_unified_base.steamclient.proto=proto/steammessages_unified_base.steamclient.proto --go_opt=Menums.proto=proto/enums.proto enums.proto

protoc --proto_path=.\proto  --go_out=.\generated --go_opt=Mgoogle/protobuf/descriptor.proto=google/protobuf/descriptor.proto  --go_opt=Msteammessages_base.proto=proto/steammessages_base.proto --go_opt=Msteammessages_auth.steamclient.proto=proto/steammessages_auth.steamclient.proto --go_opt=Msteammessages_unified_base.steamclient.proto=proto/steammessages_unified_base.steamclient.proto --go_opt=Menums.proto=proto/enums.proto steammessages_auth.steamclient.proto

protoc --proto_path=.\proto  --go_out=.\generated --go_opt=Mgoogle/protobuf/descriptor.proto=google/protobuf/descriptor.proto  --go_opt=Msteammessages_base.proto=proto/steammessages_base.proto --go_opt=Msteammessages_auth.steamclient.proto=proto/steammessages_auth.steamclient.proto --go_opt=Msteammessages_unified_base.steamclient.proto=proto/steammessages_unified_base.steamclient.proto --go_opt=Menums.proto=proto/enums.proto --go_opt=Msteammessages_clientserver_login.proto=proto/steammessages_clientserver_login.proto  steammessages_clientserver_login.proto