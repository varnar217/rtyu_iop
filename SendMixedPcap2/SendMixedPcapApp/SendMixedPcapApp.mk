##
## Auto Generated makefile by CodeLite IDE
## any manual changes will be erased      
##
## Release
ProjectName            :=SendMixedPcapApp
ConfigurationName      :=Release
WorkspaceConfiguration := $(ConfigurationName)
WorkspacePath          :=/home/elija/Projects/HTP/src/SendMixedPcap2
ProjectPath            :=/home/elija/Projects/HTP/src/SendMixedPcap2/SendMixedPcapApp
IntermediateDirectory  :=../build-$(ConfigurationName)/SendMixedPcapApp
OutDir                 :=../build-$(ConfigurationName)/SendMixedPcapApp
CurrentFileName        :=
CurrentFilePath        :=
CurrentFileFullPath    :=
User                   :=elija
Date                   :=03/11/21
CodeLitePath           :=/home/elija/.codelite
LinkerName             :=/usr/bin/g++-11
SharedObjectLinkerName :=/usr/bin/g++-11 -shared -fPIC
ObjectSuffix           :=.o
DependSuffix           :=.o.d
PreprocessSuffix       :=.i
DebugSwitch            :=-g 
IncludeSwitch          :=-I
LibrarySwitch          :=-l
OutputSwitch           :=-o 
LibraryPathSwitch      :=-L
PreprocessorSwitch     :=-D
SourceSwitch           :=-c 
OutputFile             :=../build-$(ConfigurationName)/bin/$(ProjectName)
Preprocessors          :=$(PreprocessorSwitch)NDEBUG 
ObjectSwitch           :=-o 
ArchiveOutputSwitch    := 
PreprocessOnlySwitch   :=-E
ObjectsFileList        :=$(IntermediateDirectory)/ObjectsList.txt
PCHCompileFlags        :=
LinkOptions            :=  $(LIBPCAP)/libpcap.a $(WorkspacePath)/build-$(WorkspaceConfiguration)/lib/GlobalLib.a -pthread $(shell pkg-config --libs libdpdk)
IncludePath            :=  $(IncludeSwitch). $(IncludeSwitch)$(LIBPCAP) $(IncludeSwitch)$(RESTINIO) $(IncludeSwitch)$(HTTPLIB) $(IncludeSwitch)$(NLOHMANN)/single_include $(IncludeSwitch)$(RAPIDJSON)/include $(IncludeSwitch)$(WorkspacePath)/GlobalLib 
IncludePCH             := 
RcIncludePath          := 
Libs                   := 
ArLibs                 :=  
LibPath                := $(LibraryPathSwitch). 

##
## Common variables
## AR, CXX, CC, AS, CXXFLAGS and CFLAGS can be overriden using an environment variables
##
AR       := /usr/bin/ar rcu
CXX      := /usr/bin/g++-11
CC       := /usr/bin/gcc-11
CXXFLAGS :=  -O2 -Wall -std=c++2a $(shell pkg-config --cflags libdpdk) $(Preprocessors)
CFLAGS   :=  -O2 -Wall $(Preprocessors)
ASFLAGS  := 
AS       := /usr/bin/as


##
## User defined environment variables
##
CodeLiteDir:=/usr/share/codelite
LIBPCAP:=../../../vendors/libpcap/libpcap-1.10.1
HTTPLIB:=../../../vendors/cpp-httplib/cpp-httplib-0.9.5
RESTINIO:=../../../vendors/restinio/restinio-v.0.6.13/dev
NLOHMANN:=../../../vendors/json/nlohmann/json-3.10.2
RAPIDJSON:=../../../vendors/json/rapidjson/rapidjson-1.1.0
Objects0=../build-$(ConfigurationName)/SendMixedPcapApp/main.cpp$(ObjectSuffix) ../build-$(ConfigurationName)/SendMixedPcapApp/socket_sender.cpp$(ObjectSuffix) ../build-$(ConfigurationName)/SendMixedPcapApp/http_server_httplib.cpp$(ObjectSuffix) ../build-$(ConfigurationName)/SendMixedPcapApp/pcap_reader_l.cpp$(ObjectSuffix) ../build-$(ConfigurationName)/SendMixedPcapApp/pcap_writer.cpp$(ObjectSuffix) ../build-$(ConfigurationName)/SendMixedPcapApp/pcap_reader_f.cpp$(ObjectSuffix) ../build-$(ConfigurationName)/SendMixedPcapApp/generator_app.cpp$(ObjectSuffix) ../build-$(ConfigurationName)/SendMixedPcapApp/common.cpp$(ObjectSuffix) ../build-$(ConfigurationName)/SendMixedPcapApp/http_server_api.cpp$(ObjectSuffix) 



Objects=$(Objects0) 

##
## Main Build Targets 
##
.PHONY: all clean PreBuild PrePreBuild PostBuild MakeIntermediateDirs
all: MakeIntermediateDirs $(OutputFile)

$(OutputFile): ../build-$(ConfigurationName)/SendMixedPcapApp/.d $(Objects) 
	@mkdir -p "../build-$(ConfigurationName)/SendMixedPcapApp"
	@echo "" > $(IntermediateDirectory)/.d
	@echo $(Objects0)  > $(ObjectsFileList)
	$(LinkerName) $(OutputSwitch)$(OutputFile) @$(ObjectsFileList) $(LibPath) $(Libs) $(LinkOptions)

MakeIntermediateDirs:
	@mkdir -p "../build-$(ConfigurationName)/SendMixedPcapApp"
	@mkdir -p ""../build-$(ConfigurationName)/bin""

../build-$(ConfigurationName)/SendMixedPcapApp/.d:
	@mkdir -p "../build-$(ConfigurationName)/SendMixedPcapApp"

PreBuild:


##
## Objects
##
../build-$(ConfigurationName)/SendMixedPcapApp/main.cpp$(ObjectSuffix): main.cpp ../build-$(ConfigurationName)/SendMixedPcapApp/main.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/elija/Projects/HTP/src/SendMixedPcap2/SendMixedPcapApp/main.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/main.cpp$(ObjectSuffix) $(IncludePath)
../build-$(ConfigurationName)/SendMixedPcapApp/main.cpp$(DependSuffix): main.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT../build-$(ConfigurationName)/SendMixedPcapApp/main.cpp$(ObjectSuffix) -MF../build-$(ConfigurationName)/SendMixedPcapApp/main.cpp$(DependSuffix) -MM main.cpp

../build-$(ConfigurationName)/SendMixedPcapApp/main.cpp$(PreprocessSuffix): main.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) ../build-$(ConfigurationName)/SendMixedPcapApp/main.cpp$(PreprocessSuffix) main.cpp

../build-$(ConfigurationName)/SendMixedPcapApp/socket_sender.cpp$(ObjectSuffix): socket_sender.cpp ../build-$(ConfigurationName)/SendMixedPcapApp/socket_sender.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/elija/Projects/HTP/src/SendMixedPcap2/SendMixedPcapApp/socket_sender.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/socket_sender.cpp$(ObjectSuffix) $(IncludePath)
../build-$(ConfigurationName)/SendMixedPcapApp/socket_sender.cpp$(DependSuffix): socket_sender.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT../build-$(ConfigurationName)/SendMixedPcapApp/socket_sender.cpp$(ObjectSuffix) -MF../build-$(ConfigurationName)/SendMixedPcapApp/socket_sender.cpp$(DependSuffix) -MM socket_sender.cpp

../build-$(ConfigurationName)/SendMixedPcapApp/socket_sender.cpp$(PreprocessSuffix): socket_sender.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) ../build-$(ConfigurationName)/SendMixedPcapApp/socket_sender.cpp$(PreprocessSuffix) socket_sender.cpp

../build-$(ConfigurationName)/SendMixedPcapApp/http_server_httplib.cpp$(ObjectSuffix): http_server_httplib.cpp ../build-$(ConfigurationName)/SendMixedPcapApp/http_server_httplib.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/elija/Projects/HTP/src/SendMixedPcap2/SendMixedPcapApp/http_server_httplib.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/http_server_httplib.cpp$(ObjectSuffix) $(IncludePath)
../build-$(ConfigurationName)/SendMixedPcapApp/http_server_httplib.cpp$(DependSuffix): http_server_httplib.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT../build-$(ConfigurationName)/SendMixedPcapApp/http_server_httplib.cpp$(ObjectSuffix) -MF../build-$(ConfigurationName)/SendMixedPcapApp/http_server_httplib.cpp$(DependSuffix) -MM http_server_httplib.cpp

../build-$(ConfigurationName)/SendMixedPcapApp/http_server_httplib.cpp$(PreprocessSuffix): http_server_httplib.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) ../build-$(ConfigurationName)/SendMixedPcapApp/http_server_httplib.cpp$(PreprocessSuffix) http_server_httplib.cpp

../build-$(ConfigurationName)/SendMixedPcapApp/pcap_reader_l.cpp$(ObjectSuffix): pcap_reader_l.cpp ../build-$(ConfigurationName)/SendMixedPcapApp/pcap_reader_l.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/elija/Projects/HTP/src/SendMixedPcap2/SendMixedPcapApp/pcap_reader_l.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/pcap_reader_l.cpp$(ObjectSuffix) $(IncludePath)
../build-$(ConfigurationName)/SendMixedPcapApp/pcap_reader_l.cpp$(DependSuffix): pcap_reader_l.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT../build-$(ConfigurationName)/SendMixedPcapApp/pcap_reader_l.cpp$(ObjectSuffix) -MF../build-$(ConfigurationName)/SendMixedPcapApp/pcap_reader_l.cpp$(DependSuffix) -MM pcap_reader_l.cpp

../build-$(ConfigurationName)/SendMixedPcapApp/pcap_reader_l.cpp$(PreprocessSuffix): pcap_reader_l.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) ../build-$(ConfigurationName)/SendMixedPcapApp/pcap_reader_l.cpp$(PreprocessSuffix) pcap_reader_l.cpp

../build-$(ConfigurationName)/SendMixedPcapApp/pcap_writer.cpp$(ObjectSuffix): pcap_writer.cpp ../build-$(ConfigurationName)/SendMixedPcapApp/pcap_writer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/elija/Projects/HTP/src/SendMixedPcap2/SendMixedPcapApp/pcap_writer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/pcap_writer.cpp$(ObjectSuffix) $(IncludePath)
../build-$(ConfigurationName)/SendMixedPcapApp/pcap_writer.cpp$(DependSuffix): pcap_writer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT../build-$(ConfigurationName)/SendMixedPcapApp/pcap_writer.cpp$(ObjectSuffix) -MF../build-$(ConfigurationName)/SendMixedPcapApp/pcap_writer.cpp$(DependSuffix) -MM pcap_writer.cpp

../build-$(ConfigurationName)/SendMixedPcapApp/pcap_writer.cpp$(PreprocessSuffix): pcap_writer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) ../build-$(ConfigurationName)/SendMixedPcapApp/pcap_writer.cpp$(PreprocessSuffix) pcap_writer.cpp

../build-$(ConfigurationName)/SendMixedPcapApp/pcap_reader_f.cpp$(ObjectSuffix): pcap_reader_f.cpp ../build-$(ConfigurationName)/SendMixedPcapApp/pcap_reader_f.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/elija/Projects/HTP/src/SendMixedPcap2/SendMixedPcapApp/pcap_reader_f.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/pcap_reader_f.cpp$(ObjectSuffix) $(IncludePath)
../build-$(ConfigurationName)/SendMixedPcapApp/pcap_reader_f.cpp$(DependSuffix): pcap_reader_f.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT../build-$(ConfigurationName)/SendMixedPcapApp/pcap_reader_f.cpp$(ObjectSuffix) -MF../build-$(ConfigurationName)/SendMixedPcapApp/pcap_reader_f.cpp$(DependSuffix) -MM pcap_reader_f.cpp

../build-$(ConfigurationName)/SendMixedPcapApp/pcap_reader_f.cpp$(PreprocessSuffix): pcap_reader_f.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) ../build-$(ConfigurationName)/SendMixedPcapApp/pcap_reader_f.cpp$(PreprocessSuffix) pcap_reader_f.cpp

../build-$(ConfigurationName)/SendMixedPcapApp/generator_app.cpp$(ObjectSuffix): generator_app.cpp ../build-$(ConfigurationName)/SendMixedPcapApp/generator_app.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/elija/Projects/HTP/src/SendMixedPcap2/SendMixedPcapApp/generator_app.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/generator_app.cpp$(ObjectSuffix) $(IncludePath)
../build-$(ConfigurationName)/SendMixedPcapApp/generator_app.cpp$(DependSuffix): generator_app.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT../build-$(ConfigurationName)/SendMixedPcapApp/generator_app.cpp$(ObjectSuffix) -MF../build-$(ConfigurationName)/SendMixedPcapApp/generator_app.cpp$(DependSuffix) -MM generator_app.cpp

../build-$(ConfigurationName)/SendMixedPcapApp/generator_app.cpp$(PreprocessSuffix): generator_app.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) ../build-$(ConfigurationName)/SendMixedPcapApp/generator_app.cpp$(PreprocessSuffix) generator_app.cpp

../build-$(ConfigurationName)/SendMixedPcapApp/common.cpp$(ObjectSuffix): common.cpp ../build-$(ConfigurationName)/SendMixedPcapApp/common.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/elija/Projects/HTP/src/SendMixedPcap2/SendMixedPcapApp/common.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/common.cpp$(ObjectSuffix) $(IncludePath)
../build-$(ConfigurationName)/SendMixedPcapApp/common.cpp$(DependSuffix): common.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT../build-$(ConfigurationName)/SendMixedPcapApp/common.cpp$(ObjectSuffix) -MF../build-$(ConfigurationName)/SendMixedPcapApp/common.cpp$(DependSuffix) -MM common.cpp

../build-$(ConfigurationName)/SendMixedPcapApp/common.cpp$(PreprocessSuffix): common.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) ../build-$(ConfigurationName)/SendMixedPcapApp/common.cpp$(PreprocessSuffix) common.cpp

../build-$(ConfigurationName)/SendMixedPcapApp/http_server_api.cpp$(ObjectSuffix): http_server_api.cpp ../build-$(ConfigurationName)/SendMixedPcapApp/http_server_api.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/elija/Projects/HTP/src/SendMixedPcap2/SendMixedPcapApp/http_server_api.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/http_server_api.cpp$(ObjectSuffix) $(IncludePath)
../build-$(ConfigurationName)/SendMixedPcapApp/http_server_api.cpp$(DependSuffix): http_server_api.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT../build-$(ConfigurationName)/SendMixedPcapApp/http_server_api.cpp$(ObjectSuffix) -MF../build-$(ConfigurationName)/SendMixedPcapApp/http_server_api.cpp$(DependSuffix) -MM http_server_api.cpp

../build-$(ConfigurationName)/SendMixedPcapApp/http_server_api.cpp$(PreprocessSuffix): http_server_api.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) ../build-$(ConfigurationName)/SendMixedPcapApp/http_server_api.cpp$(PreprocessSuffix) http_server_api.cpp


-include ../build-$(ConfigurationName)/SendMixedPcapApp//*$(DependSuffix)
##
## Clean
##
clean:
	$(RM) -r $(IntermediateDirectory)


