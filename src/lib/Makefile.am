MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

AM_CPPFLAGS =			-I$(srcdir)/cryptoki_compat \
			-I$(srcdir)/../common \
			-I$(srcdir)/../json \
			-I$(srcdir)/smarthsm \
			-I$(srcdir)/.. \
				@BOTAN_INCLUDES@ \
				@SQLITE3_INCLUDES@

lib_LTLIBRARIES =		libsofthsm.la
libsofthsm_la_SOURCES =		main.cpp main.h \
				osmutex.cpp osmutex.h \
				MutexFactory.cpp MutexFactory.h \
				botan_compat.cpp botan_compat.h \
				file.cpp file.h \
				log.cpp log.h \
				attribute.cpp attribute.h \
				userhandling.cpp userhandling.h \
				tokenhandling.cpp tokenhandling.h \
				mechanisms.cpp mechanisms.h \
				SoftHSMInternal.cpp SoftHSMInternal.h \
				SoftSlot.cpp SoftSlot.h \
				SoftSession.cpp SoftSession.h \
				SoftFind.cpp SoftFind.h \
				SoftDatabase.cpp SoftDatabase.h \
				SoftKeyStore.cpp SoftKeyStore.h \
				util.h \
				cryptoki.h \
				cryptoki_compat/pkcs11.h \
				../json/json.h \
				../json/jsoncpp.cpp \
				../common/ShsmApiUtils.h \
				../common/ShsmApiUtils.cpp \
				smarthsm/PK_Decryptor_EME_Remote.h \
				smarthsm/PK_Decryptor_EME_Remote.cpp \
				smarthsm/ShsmConnectionConfig.h \
				smarthsm/ShsmCreateUO.cpp \
				smarthsm/ShsmCreateUO.h \
				smarthsm/Retry.cpp \
				smarthsm/Retry.h \
				smarthsm/ShsmConnectionConfig.cpp \
				smarthsm/ShsmPrivateKey.h \
				smarthsm/ShsmPrivateKey.cpp \
				smarthsm/ShsmNullRng.h \
				smarthsm/ShsmNullRng.cpp \
				smarthsm/ShsmImportRequest.h \
				smarthsm/ShsmImportRequest.cpp \
				smarthsm/ShsmUtils.h \
				smarthsm/ShsmUtils.cpp \
				smarthsm/ShsmUserObjectInfo.h \
				smarthsm/ShsmUserObjectInfo.cpp \
				smarthsm/ShsmProcessDataRequest.h \
				smarthsm/ShsmProcessDataRequest.cpp \
				smarthsm/ShsmProcessDataRequestBuilder.h \
				smarthsm/ShsmProcessDataRequestBuilder.cpp \
				smarthsm/ShsmPrivateOperation.h \
				smarthsm/ShsmPrivateOperation.cpp \
				smarthsm/ShsmEngine.h \
				smarthsm/ShsmEngine.cpp


libsofthsm_la_LIBADD =		@BOTAN_LIBS@ @SQLITE3_LIBS@ @YIELD_LIB@
libsofthsm_la_LDFLAGS =		-version-info @VERSION_INFO@ \
				-avoid-version -module -no-undefined
