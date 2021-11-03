##
## Auto Generated makefile by CodeLite IDE
## any manual changes will be erased      
##
## Debug
ProjectName            :=GlobalLib
ConfigurationName      :=Debug
WorkspaceConfiguration := $(ConfigurationName)
WorkspacePath          :=/home/elija/Projects/HTP/src/SendMixedPcap2
ProjectPath            :=/home/elija/Projects/HTP/src/SendMixedPcap2/GlobalLib
IntermediateDirectory  :=../build-$(ConfigurationName)/GlobalLib
OutDir                 :=../build-$(ConfigurationName)/GlobalLib
CurrentFileName        :=
CurrentFilePath        :=
CurrentFileFullPath    :=
User                   :=elija
Date                   :=31/10/21
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
OutputFile             :=../build-$(ConfigurationName)/lib/$(ProjectName).a
Preprocessors          :=
ObjectSwitch           :=-o 
ArchiveOutputSwitch    := 
PreprocessOnlySwitch   :=-E
ObjectsFileList        :=$(IntermediateDirectory)/ObjectsList.txt
PCHCompileFlags        :=
LinkOptions            :=  
IncludePath            :=  $(IncludeSwitch). $(IncludeSwitch). 
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
CXXFLAGS :=  -g -std=c++2a $(Preprocessors)
CFLAGS   :=  -g $(Preprocessors)
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
Objects0=../build-$(ConfigurationName)/GlobalLib/DateTime.cpp$(ObjectSuffix) ../build-$(ConfigurationName)/GlobalLib/Log.cpp$(ObjectSuffix) 



Objects=$(Objects0) 

##
## Main Build Targets 
##
.PHONY: all clean PreBuild PrePreBuild PostBuild MakeIntermediateDirs
all: MakeIntermediateDirs ../build-$(ConfigurationName)/GlobalLib/$(OutputFile)

../build-$(ConfigurationName)/GlobalLib/$(OutputFile): $(Objects)
	@mkdir -p "../build-$(ConfigurationName)/GlobalLib"
	@echo "" > $(IntermediateDirectory)/.d
	@echo $(Objects0)  > $(ObjectsFileList)
	$(AR) $(ArchiveOutputSwitch)$(OutputFile) @$(ObjectsFileList)
	@echo rebuilt > $(IntermediateDirectory)/GlobalLib.relink

MakeIntermediateDirs:
	@mkdir -p "../build-$(ConfigurationName)/GlobalLib"
	@mkdir -p ""../build-$(ConfigurationName)/lib""

:
	@mkdir -p "../build-$(ConfigurationName)/GlobalLib"

PreBuild:


##
## Objects
##
../build-$(ConfigurationName)/GlobalLib/DateTime.cpp$(ObjectSuffix): DateTime.cpp ../build-$(ConfigurationName)/GlobalLib/DateTime.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/elija/Projects/HTP/src/SendMixedPcap2/GlobalLib/DateTime.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/DateTime.cpp$(ObjectSuffix) $(IncludePath)
../build-$(ConfigurationName)/GlobalLib/DateTime.cpp$(DependSuffix): DateTime.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT../build-$(ConfigurationName)/GlobalLib/DateTime.cpp$(ObjectSuffix) -MF../build-$(ConfigurationName)/GlobalLib/DateTime.cpp$(DependSuffix) -MM DateTime.cpp

../build-$(ConfigurationName)/GlobalLib/DateTime.cpp$(PreprocessSuffix): DateTime.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) ../build-$(ConfigurationName)/GlobalLib/DateTime.cpp$(PreprocessSuffix) DateTime.cpp

../build-$(ConfigurationName)/GlobalLib/Log.cpp$(ObjectSuffix): Log.cpp ../build-$(ConfigurationName)/GlobalLib/Log.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/elija/Projects/HTP/src/SendMixedPcap2/GlobalLib/Log.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/Log.cpp$(ObjectSuffix) $(IncludePath)
../build-$(ConfigurationName)/GlobalLib/Log.cpp$(DependSuffix): Log.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT../build-$(ConfigurationName)/GlobalLib/Log.cpp$(ObjectSuffix) -MF../build-$(ConfigurationName)/GlobalLib/Log.cpp$(DependSuffix) -MM Log.cpp

../build-$(ConfigurationName)/GlobalLib/Log.cpp$(PreprocessSuffix): Log.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) ../build-$(ConfigurationName)/GlobalLib/Log.cpp$(PreprocessSuffix) Log.cpp


-include ../build-$(ConfigurationName)/GlobalLib//*$(DependSuffix)
##
## Clean
##
clean:
	$(RM) -r $(IntermediateDirectory)


