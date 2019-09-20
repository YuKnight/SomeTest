

#coding=utf-8


import hashlib
from androguard.misc import AnalyzeAPK
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
import re
from subprocess import Popen, PIPE  # check_output

import os
import xml.etree.ElementTree as ET

import codecs

import threading

# import json
from json import * 



# from Utils import Utils
# from Utils import *


# from Scanner import *


# # from SmaliChecks 
# import SmaliChecks
# # from Configuration 
# import Configuration
# # from IntentFilter 
# import IntentFilter

# from Scanner import Utils
# from Scanner import SmaliChecks
# from Scanner import Configuration
# from Scanner import IntentFilter

# # # OK
# from .Utils import Utils
# from .SmaliChecks import SmaliChecks
# from .Configuration import Configuration
# from .IntentFilter import IntentFilter

# # from . import Utils
# # from . import SmaliChecks
# # from . import Configuration
# # from . import IntentFilter



# # modify 
from IntentFilter import *
import Utils
from core import data_flow_analysis
from core import get_register_value

class App:
    a = ""
    d = ""
    dx = ""

    NS_ANDROID_URI = "http://schemas.android.com/apk/res/android"
    NS_ANDROID = '{http://schemas.android.com/apk/res/android}'


    minSDKVersion = ""
    targetSDKVersion = ""
    packageName = ""
    versionName = ""
    versionCode = ""

    debuggable = False
    allowBackup = False

    signature_name = ""# 签名文件
    cert_info = []# 签名信息 

    permissions = []

    xml = ""
    manifest = ""
    application = ""
    exportedActivities = []
    intentFilterList = {}
    componentPermissionList = {}
    activitiesWithExcludeFromRecents = []
    activitiesExtendPreferencesWithValidate = []
    # # Fragment 注入
    activitiesExtendPreferencesWithoutValidate = []
    activitiesWithoutFlagSecure = []
    exportedReceivers = []
    exportedProviders = []
    exportedServices = []
    secretCodes = []
    libs = []
    assemblies = []
    assets = []

    rawResources = []
    dexFiles = []
    otherFiles = []

    # android P 及以上版本是否允许开启http请求需要进行配置 
    # 如果开启 则获取配置的域名信息 
    networkSecurityConfig = False
    networkSecurityConfigDomains = []



    sha256 = ""
    md5 = ""
    
    # certificate = ""

    vulnerableCheckResult = {}
    vulnerableWithCodeCheckResult = {}
    vulnerableStringCheckResult = {}

    vulnerableFieldCheckResult = {}

    # Janus高危漏洞
    isSignedV1 = False
    isSignedV2 = False

    # 单元测试配置风险 
    instrumentation = []
    # 纯 java 代码风险 
    pureJavaCode = False
    # 明文证书检测
    plainCert = []
    
    baksmaliPaths = []
    smaliChecks = None

    results = {}

    icon_path = ""# 应用图标的路径

    whiteList = ""
    # whiteList = ["Landroid/support/", 
    # "Lorg/greenrobot/", 
    # "Lnet/sqlcipher/",
    # "Lokhttp3/",
    # "Lokio/",
    # "Lretrofit2/",
    # "Lrx/",
    # "Lbutterknife/",
    # "Lcom/alibaba/fastjson/",
    # "Lcom/google/gson/",
    # "Lcom/squareup/",
    # ]

    output = ""
    filename = ""

    def output_directory(self):
        return self.output

    def export_file_path(self):
        # filename = "{}_{}_{}.txt".format(self.a.get_app_name(), self.a.get_package(), self.a.get_androidversion_name())
        # filepath = os.path.join(self.output, filename)

        # filename = "{}.txt".format(self.filename)
        # filepath = os.path.join(self.output, filename)
        filepath = os.path.join(self.output, "ScanInfo.json")
        return filepath

    def __init__(self, apk_file_path, output=""):
        print("[-]apk_file_path:{}".format(apk_file_path))

        (file_directory, temp_file_name) = os.path.split(apk_file_path)
        (file_name, extension) = os.path.splitext(temp_file_name)
        self.filename = file_name

        self.zip_out = os.path.join(file_directory, "out")
        self.apktool_out = os.path.join(file_directory, "apktoolout")
        self.so_out = os.path.join(file_directory, "so")
        self.smali_out = os.path.join(file_directory, "smali")
        
        if output != None and output != "":
            self.output = output
        else:
            self.output = file_directory
        print("[-]app output:{}".format(self.output_directory()))

        # if os.path.exists(self.export_file_path()):
        #     print("[-]report file exists")
        #     filepath = self.export_file_path()
        #     try:
        #         with open(filepath, "r") as f:
        #             self.results = "[-]done{}".format(load(f))
        #     except Exception as e:
        #         print(e)
        #     return

        self.sha256 = self.sha256CheckSum(apk_file_path)
        print("[-]sha256:{}".format(self.sha256))
        self.md5 = self.md5CheckSun(apk_file_path)
        print("[-]md5:{}".format(self.md5))
        print("[-]Parsing APK")
        self.a, self.d, self.dx = AnalyzeAPK(apk_file_path)# The three objects you get are a an APK object, d an array of DalvikVMFormat object and dx an Analysis object
        
        # # 获取应用图标 
        # icon_resolution = 0xFFFE - 1
        # icon_name = self.a.get_app_icon(max_dpi=icon_resolution)
        # print("[-]icon:{}".format(icon_name))
        # # cwd = os.path.dirname(os.path.realpath(__file__))
        # # # icon_path = os.path.join(cwd, "output_txt", icon_name.split("/")[-1])
        # # icon_dir = os.path.join(cwd, "output_txt", self.md5)
        # icon_dir = os.path.join(self.output, self.md5)
        # if not os.path.exists(icon_dir):
        #     os.mkdir(icon_dir)
        # if icon_name:
        #     print("[-]icon_dir:{}".format(icon_dir))
        #     Utils.unzipIcon(apk_file_path, icon_name, icon_dir)
        #     # self.icon_path = os.path.join(cwd, "output_txt", self.md5, icon_name.split("/")[-1])
        #     self.icon_path = os.path.join(self.output, self.md5, icon_name.split("/")[-1])




        # # 从文件中读取白名单 
        self.load_white_list()

        # # self.extractCertificate()
        # # print(self.extractCertificateInformation(self.a))

        # # 签名信息 
        # self.extractCertificate()
        self.extractCertificateInformation(self.a)

        # Janus高危漏洞
        self.isSignedV1 = self.a.is_signed_v1()
        self.isSignedV2 = self.a.is_signed_v2()

        # self.checkVulnerables()# 放到单独的线程中去 
        # print(self.vulnerableStringCheckResult)
        # self.vulnerableCheckField()
        # self.load_vulnerable_feature()
        # self.load_config_check()# 暂时替换成这个进行测试 
        # self.load_config_check(self.load_vulnerable_feature())
        
        self.manifest = self.a.get_android_manifest_axml().get_xml_obj()# lxml.etree.Element
        self.application = self.manifest.findall("application")[0]
        print("[-]Gathering Information")
        print("   [-]Package Properties")
        self.extractPackageProperties()# 需要检测配置的xml文件 

        # 单元测试配置风险  需要实测 
        instrumentations = self.manifest.findall("instrumentation")# ???  只取第一个 ???
        if 0 < len(self.instrumentation):
            instrumention_config = []
            for instru in self.instrumentation:
                self.instrumentation.append([instru.get(self.NS_ANDROID + "name"), instru.get(self.NS_ANDROID + "targetPackage")])

        print("   [-]Exported Components")
        self.extractExportedComponents()# 四大组件导出 不太符合需求 需要找到检测特征后进行修改 

        print("   [-]Files")
        self.extractFiles()# 检测加固 ???  如果加固则尝试脱壳并用脱壳后的dex进行扫描 ??? 

        # 纯 java 代码风险 检测是否有so文件
        if 0 == len(self.libs):
            self.pureJavaCode = True

        # # # 明文证书检测 检测 cer 后缀的文件  不全 !!! 
        # # if 0 < len(self.assets):
        # #     for f in self.assets:
        # #         if ".cer" in f:
        # #             self.plainCert.append(f)
        # # # MobSF 检测证书文件的方式 !!! 
        # # files = self.a.get_files()
        # # for file_name in files:
        # #     ext = file_name.split('.')[-1]
        # #     if re.search("cer|pem|cert|crt|pub|key|pfx|p12", ext):
        # #         certz += escape(file_name)
        # #     if re.search("jks|bks", ext):
        # #         key_store += escape(file_name)
        # files = self.a.get_files()
        for file_name in files:
            ext = file_name.split('.')[-1]
            if re.search("cer|pem|cert|crt|pub|key|pfx|p12", ext):
                self.plainCert.append(file_name)
        

        # # 需要检测资源文件跟dex代码中是否存在 手机号 邮箱地址 账号密码等信息  !!! 


    # Return the SHA256 of the APK file.
    def sha256CheckSum(self, filename):
        f = open(filename, 'rb')
        contents = f.read()
        return hashlib.sha256(contents).hexdigest()
    
    def md5CheckSun(self, filepath):
        f = open(filepath, 'rb')
        contents = f.read()
        return hashlib.md5(contents).hexdigest()

    # Extract package properties such as the minSDKVersion, PackageName, VersionName, VersionCode, isDebuggable, allowBackup
    def extractPackageProperties(self):
        usesSDK = self.manifest.findall("uses-sdk")
        self.minSDKVersion = self.a.get_min_sdk_version()
        self.targetSDKVersion = self.a.get_target_sdk_version()
        self.packageName = self.a.get_package()
        self.versionName = self.a.get_androidversion_name()
        self.versionCode = self.a.get_androidversion_code()
        if self.application.get(self.NS_ANDROID + "debuggable") == 'true':
            self.debuggable = True
        
        # 数据备份配置风险 
        if self.application.get(self.NS_ANDROID + "allowBackup") == 'true':
            self.allowBackup = True
        elif self.application.get(self.NS_ANDROID + "allowBackup") == 'false':
            self.allowBackup = False
        else:
            self.allowBackup = True
        
        # # android P 及以上版本 允许开启http请求需要进行配置 
        # # 需要解析 resources.arsc 中相应的xml文件
        # if self.application.get(self.NS_ANDROID + "networkSecurityConfig") is not None:
        #     self.networkSecurityConfig = True
        #     self.parseNetworkSecurityConfigFiles()

    def apktool_folder(self):
        # cwd = os.path.dirname(os.path.realpath(__file__))
        # return cwd + "/output_apktool/" + self.a.get_package() + "_" + self.a.get_androidversion_code()
        return self.apktool_out

    def parseNetworkSecurityConfigFiles(self):
        xml_path = os.path.join(self.apktool_folder(), "res/xml")
        config_file = os.path.join(xml_path, "network_security_config.xml")

        xml_files = []
        if os.path.isfile(config_file):
            xml_files.append(config_file)
        elif os.path.isdir(xml_path):
            for root, dirs, files in os.walk(xml_path):
                xml_files = [os.path.join(root, f) for f in files if f.endswith(".xml")]

        for file_path in xml_files:
            tree = ET.parse(file_path)# AXMLPrinter(read(inp)).get_xml_obj()
            root = tree.getroot()
            self.parseNetworkSecurityConfigFile(root)

    def parseNetworkSecurityConfigFile(self, root):
        foundConfig = False

        for child in root:
            if child.tag == "base-config" or child.tag == "domain-config":
                domainConfig = {
                    'domains': [],
                    'allowClearText': True,
                    'allowUserCA': False,
                    'pinning': False,
                    'pinningExpiration': ''
                }
                if 'cleartextTrafficPermitted' in child.attrib:
                    if child.attrib['cleartextTrafficPermitted'] == "false":
                        domainConfig['allowClearText'] = False
                for sub in child:
                    if sub.tag == "domain":
                        domainConfig['domains'].append(sub.text)
                    if sub.tag == "trust-anchors":
                        for certificates in sub:
                            if certificates.attrib['src'] == "user":
                                domainConfig['allowUserCA'] = True
                    if sub.tag == "pin-set":
                        domainConfig['pinning'] = True
                        if 'expiration' in sub.attrib:
                            domainConfig['pinningExpiration'] = sub.attrib['expiration']
                self.networkSecurityConfigDomains.append(domainConfig)
                foundConfig = True

        return foundConfig


    # Create the list of permissions used by the package
    def extractPermissions(self):
        # cwd = os.path.dirname(os.path.realpath(__file__))  # 
        # path = os.path.join(cwd, "permissions.txt")
        # per = Utils.loadRiskPermission(path)
        per = self.load_risk_permission()
        for permission in self.a.get_permissions():
            if None != per and 0 < len(per):
                if str(permission) in per and str(permission) not in self.permissions:
                    self.permissions.append(str(permission))

    def extractCertificate(self):
        self.signature_name = self.a.get_signature_name()
    
    # 获取证书信息
    def extractCertificateInformation(self, a) :
        '''
        @param a : an APK instance
        
        @rtype : a certificate object by giving the name in the apk file
        '''
        # cert_info = []
        self.cert_info.append("APK is signed: %s" % a.is_signed())
        
        for index,cert in enumerate(a.get_certificates()):
            self.cert_info.append("Certificate #%s" % index)
            cert_info_issuer = ["Issuer:", cert.issuer.human_friendly]
            cert_info_subject = ["Subject:", cert.subject.human_friendly]
            
            self.cert_info.extend(cert_info_issuer)
            self.cert_info.extend(cert_info_subject)
            
            self.cert_info.append("Serial number: %s" % cert.serial_number)
            self.cert_info.append("Hash algorithm: %s" % cert.hash_algo)
            self.cert_info.append("Signature algorithm: %s" % cert.signature_algo)
            self.cert_info.append("SHA-1 thumbprint: %s" % codecs.encode(cert.sha1, 'hex').decode())
            self.cert_info.append("SHA-256 thumbprint: %s" % codecs.encode(cert.sha256, 'hex').decode())
        
        return self.cert_info
    

    # # Check for the presence of a SECRET_CODE in the object and add it to a global list of objects with SECRET_CODEs.
    # def checkForSecretCodes(self, object):
    #     intentFilters = object.findall("intent-filter")
    #     for intentFilter in intentFilters:
    #         if len(intentFilter.findall("data")) > 0:
    #             datas = intentFilter.findall("data")
    #             for data in datas:
    #                 if data.get(self.NS_ANDROID + "scheme") == "android_secret_code":
    #                     self.secretCodes.append(data.get(self.NS_ANDROID + "host"))
    
    def checkForSecretCodes(self, object):
        pass

    # Create a global list of activities with the excludeFromRecents attribute
    def extractActivitiesWithExcludeFromRecents(self):
        for activity in self.application.findall("activity"):
            if activity.get(self.NS_ANDROID + "excludeFromRecents") == 'true':
                self.activitiesWithExcludeFromRecents.append(activity.get(self.NS_ANDROID + "name"))

    # Create a global list of activities that do not have the FLAG_SECURE or the excludeFromRecents attribute set.
    def extractActivitiesWithoutSecureFlag(self):# 检测交叉引用中是否存在值为0x200 dx.find_methods(classname="Landroid/view/Window", methodname="setFlags")
        activitiesWithoutSecureFlag = []
        for activity in self.a.get_activities():
            if self.doesActivityHasFlagSecure(activity) is False and activity not in self.getActivitiesWithExcludeFromRecents():
                try:
                    activity.encode("ascii")
                except UnicodeEncodeError as e:
                    activity = activity.encode('ascii', 'xmlcharrefreplace')
                self.activitiesWithoutFlagSecure.append(activity)

    # Return the ProtectionLevel of a particular Permission
    def determinePermissionProtectionLevel(self, targetPermission):
        for permission in self.manifest.findall("permission"):
            if permission.get(self.NS_ANDROID + "name") == targetPermission:
                print(permission.get(self.NS_ANDROID + "protectionLevel"))
        return ""

    # Add the extracted permission of a particular component to a global list indexed by the component name.
    def extractComponentPermission(self, component):
        if component.get(self.NS_ANDROID + "permission") is not None:
            self.componentPermissionList[component.get(self.NS_ANDROID + "name")] = component.get(self.NS_ANDROID + "permission")

    # Create a global list with that particular object intent-filters indexed to the component name.
    def extractIntentFilters(self, filters, obj):
        filterList = []
        name = obj.get(self.NS_ANDROID + "name")
        filters = obj.findall("intent-filter")
        for filter in filters:
            intentFilter = IntentFilter()
            for action in filter.findall("action"):
                intentFilter.addAction(action.get(self.NS_ANDROID + "name"))
            for category in filter.findall("category"):
                intentFilter.addCategory(category.get(self.NS_ANDROID + "name"))
            for data in filter.findall("data"):
                if data.get(self.NS_ANDROID + "scheme") is not None:
                    intentFilter.addData("scheme:" + data.get(self.NS_ANDROID + "scheme"))
                if data.get(self.NS_ANDROID + "host") is not None:
                    intentFilter.addData("host:" + data.get(self.NS_ANDROID + "host"))
                if data.get(self.NS_ANDROID + "port") is not None:
                    intentFilter.addData("port:" + data.get(self.NS_ANDROID + "port"))
                if data.get(self.NS_ANDROID + "path") is not None:
                    intentFilter.addData("path:" + data.get(self.NS_ANDROID + "path"))
                if data.get(self.NS_ANDROID + "pathPattern") is not None:
                    intentFilter.addData("pathPattern:" + data.get(self.NS_ANDROID + "pathPattern"))
                if data.get(self.NS_ANDROID + "pathPrefix") is not None:
                    intentFilter.addData("pathPrefix:" + data.get(self.NS_ANDROID + "pathPrefix"))
                if data.get(self.NS_ANDROID + "mimeType") is not None:
                    intentFilter.addData("mimeType:" + data.get(self.NS_ANDROID + "mimeType"))
            filterList.append(intentFilter.toDict())

        self.intentFilterList[name] = filterList

    # Determine exported Activities taking into account the existence of exported attribute or the presence of intent-filters and also check for presence of secretCode and if vulnerable to Fragment Injection
    # Check if any of the activities (exported or not) have any SECRET_CODE configured.
    def extractExportedActivities(self):
        for activity in self.application.findall("activity"):
            activityName = activity.get(self.NS_ANDROID + "name")
            if activityName.startswith("."):
                activityName = self.packageName + activityName
            
            self.checkForSecretCodes(activity)# 
            # if len(activity.findall("intent-filter")) > 0:
            #     filters = activity.findall("intent-filter")
            #     self.extractIntentFilters(filters, activity)
            
            if activity.get(self.NS_ANDROID + "exported") == 'true':
                self.extractComponentPermission(activity)
                self.exportedActivities.append(activityName)

                if self.doesActivityExtendsPreferenceActivity(activityName) is True:
                    if self.doesPreferenceActivityHasValidFragmentCheck(activityName) is False:# Fragment 注入
                        try:
                            activityName.encode("ascii")
                        except UnicodeEncodeError as e:
                            activityName = activityName.encode('ascii', 'xmlcharrefreplace')
                        self.activitiesExtendPreferencesWithoutValidate.append(activityName)
            elif activity.get(self.NS_ANDROID + "exported") != 'false':
                if len(activity.findall("intent-filter")) > 0:
                    # # self.extractIntentFilters(filters, activity)
                    # filters = activity.findall("intent-filter")
                    # self.extractIntentFilters(filters, activity)

                    self.extractComponentPermission(activity)
                    self.exportedActivities.append(activityName)
                    
                    if self.doesActivityExtendsPreferenceActivity(activityName) is True:
                        if self.doesPreferenceActivityHasValidFragmentCheck(activityName) is False:
                            try:
                                activityName.encode("ascii")
                            except UnicodeEncodeError as e:
                                activityName = activityName.encode('ascii', 'xmlcharrefreplace')
                            self.activitiesExtendPreferencesWithoutValidate.append(activityName)


    # Determine exported Broadcast Receivers taking into account the existence of exported attribute or the presence of intent-filters
    def extractExportedReceivers(self):
        for receiver in self.application.findall("receiver"):
            receiverName = receiver.get(self.NS_ANDROID + "name")
            self.checkForSecretCodes(receiver)
            if receiver.get(self.NS_ANDROID + "exported") == 'true':
                # if len(receiver.findall("intent-filter")) > 0:
                #     filters = receiver.findall("intent-filter")
                #     self.extractIntentFilters(filters, receiver)
                #     self.extractComponentPermission(receiver)
                self.exportedReceivers.append(receiverName)
            elif receiver.get(self.NS_ANDROID + "exported") != 'false':
                if len(receiver.findall("intent-filter")) > 0:
                    # filters = receiver.findall("intent-filter")
                    # self.extractIntentFilters(filters, receiver)
                    # self.extractComponentPermission(receiver)
                    self.exportedReceivers.append(receiverName)

    # Determine exported Content Providers taking into account the existence of exported attribute or without the attributes, under API 16 they are exported by default
    # def extractExportedProviders(self):
    #     for provider in self.application.findall("provider"):
    #         providerName = provider.get(self.NS_ANDROID + "name")

    #         # Hack: some apps have their manifest with relative provider names
    #         if providerName.startswith("."):
    #             providerName = provider.get(self.NS_ANDROID + "authorities")

    #         self.checkForSecretCodes(provider)
    #         if provider.get(self.NS_ANDROID + "exported") == 'true':
    #             self.exportedProviders.append(providerName)
    #             # self.smaliChecks.determineContentProviderSQLi(providerName)
    #             # self.smaliChecks.determineContentProviderPathTraversal(providerName)
    #         elif provider.get(self.NS_ANDROID + "exported") != 'false':
    #             if int(self.minSDKVersion) <= 16:
    #                 self.extractComponentPermission(provider)
    #                 # self.smaliChecks.determineContentProviderSQLi(providerName)
    #                 # self.smaliChecks.determineContentProviderPathTraversal(providerName)
    #                 self.exportedProviders.append(providerName + " * In devices <= API 16 (Jelly Bean 4.1.x);")

    # 根据 https://developer.android.com/guide/topics/manifest/provider-element?hl=zh-CN#exported 
    def extractExportedProviders(self):
        for provider in self.application.findall("provider"):
            providerName = provider.get(self.NS_ANDROID + "name")

            # Hack: some apps have their manifest with relative provider names
            if providerName.startswith("."):
                providerName = provider.get(self.NS_ANDROID + "authorities")

            self.checkForSecretCodes(provider)
            # if int(self.minSDKVersion) <= 16:
            if self.minSDKVersion != None and int(self.minSDKVersion) <= 16:
                self.extractComponentPermission(provider)
                self.exportedProviders.append(providerName)
            else:
                if provider.get(self.NS_ANDROID + "exported") == 'true':
                    self.exportedProviders.append(providerName)
                #     # self.smaliChecks.determineContentProviderSQLi(providerName)
                #     # self.smaliChecks.determineContentProviderPathTraversal(providerName)
                # elif provider.get(self.NS_ANDROID + "exported") != 'false':
                #     if int(self.minSDKVersion) <= 16:
                #         self.extractComponentPermission(provider)
                #         # self.smaliChecks.determineContentProviderSQLi(providerName)
                #         # self.smaliChecks.determineContentProviderPathTraversal(providerName)
                #         self.exportedProviders.append(providerName + " * In devices <= API 16 (Jelly Bean 4.1.x);")
                # elif activities[1].get(NS_ANDROID + "exported") == None:# 未明确写明的情况




    # Determine exported Services taking into account the existence of exported attribute or the presence of intent-filters
    def extractExportedServices(self):
        for service in self.application.findall("service"):
            serviceName = service.get(self.NS_ANDROID + "name")
            self.checkForSecretCodes(service)
            if service.get(self.NS_ANDROID + "exported") == 'true':
                # if len(service.findall("intent-filter")) > 0:
                #     filters = service.findall("intent-filter")
                #     self.extractComponentPermission(service)
                #     self.extractIntentFilters(filters, service)
                self.exportedServices.append(serviceName)
            elif service.get(self.NS_ANDROID + "exported") != 'false':# None
                if len(service.findall("intent-filter")) > 0:
                    # filters = service.findall("intent-filter")
                    # self.extractIntentFilters(filters, service)
                    # self.extractComponentPermission(service)
                    self.exportedServices.append(serviceName)

    # Run the functions that extract the exported components.
    def extractExportedComponents(self):
        self.extractExportedActivities()
        self.extractExportedReceivers()
        self.extractExportedProviders()
        self.extractExportedServices()

    # Return the app permissions global list
    def getPermissions(self):
        return self.permissions

    # Return the exported activities global list
    def getExportedActivities(self):
        return self.exportedActivities

    # Return the the exported broadcast receivers global list
    def getExportedReceivers(self):
        return self.exportedReceivers

    # Return the exported content providers global list
    def getExportedProviders(self):
        return self.exportedProviders

    # Return the exported services global list
    def getExportedServices(self):
        return self.exportedServices

    # Return the app package name
    def getPackageName(self):
        return self.packageName

    # Return the app minSDKVersion
    def getMinSDKVersion(self):
        return self.minSDKVersion

    # Return the app targetSDKVersion
    def getTargetSDKVersion(self):
        return self.targetSDKVersion

    # Return the app versionName
    def getVersionName(self):
        return self.versionName

    # Return the app versionCode
    def getVersionCode(self):
        return self.versionCode

    # Return the APK SHA256
    def getSHA256(self):
        return self.sha256

    # Return the permission defined in the particular component.
    def getComponentPermission(self, name):
        try:
            return self.componentPermissionList[name]
        except:
            return ""


    def isDebuggable(self):
        if self.debuggable is True:
            return "Yes"
        else:
            return "No"

    def isBackupEnabled(self):
        if self.allowBackup is True:
            return "Yes"
        else:
            return "No"

    def hasNetworkSecurityConfig(self):
        return self.networkSecurityConfig

    def isMultiDex(self):
        if len(self.getDexFiles()) > 1:
            return "Yes"
        else:
            return "No"

    def getAssets(self):
        return self.assets


    def getRawResources(self):
        return self.rawResources

    def getLibs(self):
        return self.libs

    def getOtherFiles(self):
        return self.otherFiles


    def getDexFiles(self):
        return self.dexFiles

    def getSecretCodes(self):
        return self.secretCodes

    def getIntentFiltersList(self):
        return self.intentFilterList

    def getNetworkSecurityConfigDomains(self):
        return self.networkSecurityConfigDomains



    # Create a list of files, organized in several types and while doing it, by the existence of certain files, determine if the app is a Cordova or Xamarin app.
    def extractFiles(self):
        files = self.a.get_files()
        try:
            for f in files:
                # # 中文文件名解析有问题 
                # try:
                #     f.encode("ascii")
                # except UnicodeEncodeError as e:
                #     f = f.encode('ascii', 'xmlcharrefreplace')

                if f[0:4] == "lib/":
                    self.libs.append(f)
                elif f[0:11] == "assemblies/" in f:
                    self.assemblies.append(f)
                elif "assets/" in f:
                    self.assets.append(f)
                elif "res/raw/" in f:
                    self.rawResources.append(f)
                elif ".dex" in f:
                    self.dexFiles.append(f)
                else:
                    # 过滤一下 资源文件 
                    if not f.startswith("R/"):
                        self.otherFiles.append(f)
        except UnicodeDecodeError as e:
            pass

    def getActivitiesWithExcludeFromRecents(self):
        return self.activitiesWithExcludeFromRecents

    def getActivitiesWithoutSecureFlag(self):
        return self.activitiesWithoutFlagSecure

    def getActivitiesExtendPreferencesWithValidate(self):
        return self.activitiesExtendPreferencesWithValidate

    def getActivitiesExtendPreferencesWithoutValidate(self):
        return self.activitiesExtendPreferencesWithoutValidate


    def getAnalysis(self):
        attrs = [
            "minSDKVersion",
            "targetSDKVersion",
            "packageName",
            "versionName",
            "versionCode",

            "debuggable",# 
            "allowBackup",# 数据备份配置风险

            "signature_name",
            "cert_info",

            "permissions",

            "exportedActivities",
            "intentFilterList",

            "componentPermissionList",

            "activitiesWithExcludeFromRecents",
            "activitiesExtendPreferencesWithValidate",
            "activitiesExtendPreferencesWithoutValidate",
            "activitiesWithoutFlagSecure",

            "exportedReceivers",
            "exportedProviders",
            "exportedServices",
            "secretCodes",
            
            # "libs",
            # "assemblies",
            # "assets",
            # "rawResources",
            # "dexFiles",
            # "otherFiles",

            "networkSecurityConfig",
            "networkSecurityConfigDomains",

            "sha256",
            "md5",
            # "certificate",

            
            "vulnerableCheckResult",
            "vulnerableWithCodeCheckResult",
            "vulnerableStringCheckResult",

            "vulnerableFieldCheckResult",

            "isSignedV1",
            "isSignedV2",
            "instrumentation",
            "pureJavaCode",# 纯java代码风险
            "plainCert",
        ]
        data = {}
        for attr in attrs:
            value = getattr(self, attr)
            if isinstance(value, list):
                try:
                    value = sorted(value)
                except TypeError:
                    pass
            elif callable(value):# callable() 函数用于检查一个对象是否是可调用的。如果返回 True，object 仍然可能调用失败；但如果返回 False，调用对象 object 绝对不会成功。对于函数、方法、lambda 函式、 类以及实现了 __call__ 方法的类实例, 它都返回 True。 
                value = value()

            data[attr] = value

        return data
    
    def get_results(self):
        print("[-]Exporting analysis")
        self.exportAnalysis()
        return self.results

    def exportAnalysis(self):
        content = {}
        data = self.getAnalysis()
        for elem in sorted(data.items()):
            content[elem[0]] = elem[1]

        jsonValue = JSONEncoder().encode(content)
        # filepath = self.export_file_path()
        # with open(filepath, "w") as file:
        #     dump(jsonValue, file)

        self.results = jsonValue
        return 
    

    def exportAnalysisToFormatTxt(self):
        content = {}
        data = self.getAnalysis()
        for elem in sorted(data.items()):
            content[elem[0]] = elem[1]

        # # jsonValue = JSONEncoder().encode(content)
        # # cwd = os.path.dirname(os.path.realpath(__file__))
        # # filename = self.a.get_package() + "_" + self.a.get_androidversion_code() + "_" + self.md5 + ".json"
        # # # filddir = os.path.join(cwd, "output_txt", self.md5)
        # # filename = "{}_{}_{}.txt".format(self.a.get_app_name(), self.a.get_package(), self.a.get_androidversion_name())
        # filename = "{}.txt".format(self.filename)
        # filepath = os.path.join(self.output, filename)
        filepath = self.export_file_path()
        self.writeToFile(filepath, content)
        
    def writeToFile(self, filepath, content):
        with open(filepath, "w+", encoding='utf-8') as f:
            f.writelines("app名称\t{}\n包名\t{}\n版本\t{}\n".format(self.a.get_app_name(), self.a.get_package(), self.a.get_androidversion_name()))
            itemIdx = 0
            jv = content["vulnerableCheckResult"]
            # jv = content["vulnerableStringCheckResult"]
            # jv = content["vulnerableWithCodeCheckResult"]
            if len(jv["0x80000101"]) > 0 or len(jv["0x80000102"]) > 0 or len(jv["0x80000103"]) > 0 or len(jv["0x80000104"]) > 0 or len(jv["0x80000105"]) > 0:
                itemIdx = itemIdx + 1
                f.writelines("{} 应用读取设备IMEI(国际移动设备身份识别码)\n".format(itemIdx))
                subIdx = 1
                for item in jv["0x80000101"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
                for item in jv["0x80000102"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
                for item in jv["0x80000103"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
                for item in jv["0x80000104"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
                for item in jv["0x80000105"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
            f.writelines("\n")
            
            if len(jv["0x80000201"]) > 0 or len(jv["0x80000202"]) > 0 or len(jv["0x80000203"]) > 0 or len(jv["0x80000204"]) > 0 or len(jv["0x80000205"]) > 0:
                itemIdx = itemIdx + 1
                f.writelines("{} 应用读取设备SIM卡IMSI(国际移动用户识别码)\n".format(itemIdx))
                subIdx = 1
                for item in jv["0x80000201"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
                for item in jv["0x80000202"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
                for item in jv["0x80000203"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
                for item in jv["0x80000204"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
                for item in jv["0x80000205"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
            f.writelines("\n")

            if len(jv["0x80000301"]) > 0 or len(content["vulnerableStringCheckResult"]["0x80000303"]) > 0 or len(content["vulnerableStringCheckResult"]["0x80000304"]) > 0:
                itemIdx = itemIdx + 1
                f.writelines("{} 应用监听手机通话状态\n".format(itemIdx))
                subIdx = 1
                for item in jv["0x80000301"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
                for item in content["vulnerableStringCheckResult"]["0x80000303"]:
                    f.writelines("\t{} {}\n".format(subIdx, item[1]))
                    subIdx = subIdx + 1
                for item in content["vulnerableStringCheckResult"]["0x80000304"]:
                    f.writelines("\t{} {}\n".format(subIdx, item[1]))
                    subIdx = subIdx + 1
            f.writelines("\n")

            if len(jv["0x80000401"]) > 0 or len(jv["0x80000402"]) > 0 or len(jv["0x80000403"]) > 0 or len(jv["0x80000404"]) > 0 or len(jv["0x80000405"]) > 0:
                itemIdx = itemIdx + 1
                f.writelines("{} 应用通过网络或卫星进行设备定位 获取本低手机GPS位置\n".format(itemIdx))
                subIdx = 1
                for item in jv["0x80000401"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
                for item in jv["0x80000402"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
                for item in jv["0x80000403"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
                for item in jv["0x80000404"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
                for item in jv["0x80000405"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
            f.writelines("\n")
            
            if len(jv["0x80000501"]) > 0:
                itemIdx = itemIdx + 1
                f.writelines("{} 应用获取手机号码\n".format(itemIdx))
                subIdx = 1
                for item in jv["0x80000501"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
            f.writelines("\n")

            if len(jv["0x80000701"]) > 0:
                itemIdx = itemIdx + 1
                f.writelines("{} 存储卡的操作行为\n".format(itemIdx))
                subIdx = 1
                for item in jv["0x80000701"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
            f.writelines("\n")

            if len(content["vulnerableStringCheckResult"]["0x80000801"]) > 0 or len(content["vulnerableStringCheckResult"]["0x80000802"]) > 0:
                itemIdx = itemIdx + 1
                f.writelines("{} 访问联系人通讯录信息\n".format(itemIdx))
                subIdx = 1
                for item in content["vulnerableStringCheckResult"]["0x80000801"]:
                    f.writelines("\t{} {}\n".format(subIdx, item[1]))
                    subIdx = subIdx + 1
                for item in content["vulnerableStringCheckResult"]["0x80000802"]:
                    f.writelines("\t{} {}\n".format(subIdx, item[1]))
                    subIdx = subIdx + 1
            f.writelines("\n")

            if len(jv["0x80000A01"]) > 0 or len(jv["0x80000A02"]) > 0 or len(jv["0x80000A03"]) > 0:
                itemIdx = itemIdx + 1
                f.writelines("{} 发送短信\n".format(itemIdx))
                subIdx = 1
                for item in jv["0x80000A01"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
                for item in jv["0x80000A02"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
                for item in jv["0x80000A03"]:
                    f.writelines("\t{} {}\n".format(subIdx, item))
                    subIdx = subIdx + 1
            f.writelines("\n")

            if len(content["vulnerableStringCheckResult"]["0x80000B01"]) > 0 or len(content["vulnerableStringCheckResult"]["0x80000B02"]) > 0 or len(content["vulnerableStringCheckResult"]["0x80000B03"]) > 0 or len(content["vulnerableStringCheckResult"]["0x80000B04"]) > 0 or len(content["vulnerableStringCheckResult"]["0x80000B05"]) > 0 or len(content["vulnerableStringCheckResult"]["0x80000B06"]) > 0 or len(content["vulnerableStringCheckResult"]["0x80000B07"]) > 0:
                itemIdx = itemIdx + 1
                f.writelines("{} 读取短信\n".format(itemIdx))
                subIdx = 1
                for item in content["vulnerableStringCheckResult"]["0x80000B01"]:
                    f.writelines("\t{} {}\n".format(subIdx, item[1]))
                    subIdx = subIdx + 1
                for item in content["vulnerableStringCheckResult"]["0x80000B02"]:
                    f.writelines("\t{} {}\n".format(subIdx, item[1]))
                    subIdx = subIdx + 1
                for item in content["vulnerableStringCheckResult"]["0x80000B03"]:
                    f.writelines("\t{} {}\n".format(subIdx, item[1]))
                    subIdx = subIdx + 1
                for item in content["vulnerableStringCheckResult"]["0x80000B04"]:
                    f.writelines("\t{} {}\n".format(subIdx, item[1]))
                    subIdx = subIdx + 1
                for item in content["vulnerableStringCheckResult"]["0x80000B05"]:
                    f.writelines("\t{} {}\n".format(subIdx, item[1]))
                    subIdx = subIdx + 1
                for item in content["vulnerableStringCheckResult"]["0x80000B06"]:
                    f.writelines("\t{} {}\n".format(subIdx, item[1]))
                    subIdx = subIdx + 1
                for item in content["vulnerableStringCheckResult"]["0x80000B07"]:
                    f.writelines("\t{} {}\n".format(subIdx, item[1]))
                    subIdx = subIdx + 1
            f.writelines("\n")

        # self.results = "[-]done{}".format(filepath)
        self.results = "[-]done{}".format(self.export_file_path())



    # 
    def determineContentProviderSQLi(self,provider):
        provider_dex_name = convert_canonical_to_dex(provider)
        meth = self.dx.find_methods(classname=provider_dex_name, methodname="query")
        for m in meth:
            xrefTo = m.get_xref_to()
            for x in xrefTo:
                ca, ecMeth, idx = x
                if "Landroid/database/sqlite/SQLiteDatabase;" == ca.name and "query" == ecMeth.get_name():
                    # 寻找是否是 \? 模式 否则存在sql注入 
                    pass
                else:
                    continue
    # 另一种查找方式 self.dx.find_methods(classname="Landroid/database/sqlite/SQLiteDatabase;", methodname="query")
    # 在使用的地方查找其值  只能查找明文字符串的query !!! 
    # def determineContentProviderSQLi(self,provider):


    def doesActivityHasFlagSecure(self,activity):
        pass


    def doesActivityExtendsPreferenceActivity(self,activity):
        isExtends = False
        activity_dex_name = convert_canonical_to_dex(activity)
        for item in self.d:
            if None != item.get_class(activity_dex_name):
                super_clz_dex_name = item.get_class(activity_dex_name).get_superclassname()
                if super_clz_dex_name == "Landroid/preference/PreferenceActivity;":
                    isExtends = True
                    break
        return isExtends


    def doesPreferenceActivityHasValidFragmentCheck(self,activity):
        activity_dex_name = convert_canonical_to_dex(activity)
        found = self.dx.find_methods(classname=activity_dex_name, methodname="isValidFragment")# generator 为空会导致异常 
        if 0 != len(list(found)):
            return True
        else:
            return False





    def vulnerableCheckField(self):
        self.vulnerableFieldCheckResult = {}
        vulneras = {
            {
			"vulnerableType": "0x80000601",
			"className": "Landroid/os/Build;",
			"fieldName": "FINGERPRINT"
            },
            {
			"vulnerableType": "0x80000602",
			"className": "Landroid/os/Build;",
			"fieldName": "MANUFACTURER"
            },
            {
			"vulnerableType": "0x80000603",
			"className": "Landroid/os/Build;",
			"fieldName": "BOARD"
            },
        }
        for vulnera in vulneras:
            vulnerableType = vulnera["vulnerableType"]
            className = vulnera["className"]
            fieldName = vulnera["fieldName"]
            
            self.vulnerableFieldCheckResult[vulnerableType] = []
            field_found = self.dx.find_fields(classname=className, fieldname=fieldName)# 找到多条 ???????? 
            for field in field_found:# 一般来说应该只找到一个 !!! 
                xref_read = field.get_xref_read()
                caller = []
                for x in xref_read:
                    ca, ecMeth = x
                    caller.append("{}->{}{}".format(ca.name, ecMeth.get_name(), ecMeth.get_descriptor().replace(" ", "")))
                self.vulnerableFieldCheckResult[vulnerableType].append(caller)
        return self.vulnerableFieldCheckResult





    
    # 只检测是否出现 如果同一个 vulnerableType 会出现覆盖的情况 !!!!!!!!!!!!!
    def vulnerableChecks(self, vulneras):
        self.vulnerableCheckResult = {}
        for vulnera in vulneras:
            vulnerableType = vulnera["vulnerableType"]
            className = vulnera["className"]
            methodName = vulnera["methodName"]
            descriptor = vulnera["descriptor"]
            self.vulnerableCheckResult[vulnerableType] = []
            method_found = self.dx.find_methods(classname=className, methodname=methodName)# 找到多条 ???????? 
            for meth in method_found:
                xref_from = meth.get_xref_from()
                caller = []# 需要排重 ??? 同一个函数中多次出现 ??? 
                for x in xref_from:
                    ca, ecMeth, idx = x
                    # 增加白名单过滤 
                    # 只有某些类型的进行过滤, 非全局过滤
                    if "0x80000101" == vulnerableType or "0x80000201" == vulnerableType or "0x80000301" == vulnerableType or "0x80000701"==vulnerableType:
                        if any(ca.name.startswith(item) for item in self.whiteList):
                            continue
                    
                    self.vulnerableCheckResult[vulnerableType].append("{}->{}{}".format(ca.name, ecMeth.get_name(), ecMeth.get_descriptor().replace(" ", "")))                    
                #     caller.append("{}->{}{}".format(ca.name, ecMeth.get_name(), ecMeth.get_descriptor().replace(" ", "")))
                # if 0 < len(caller):# if 0 < len(caller) and caller not in self.vulnerableCheckResult[vulnerableType]:
                #     self.vulnerableCheckResult[vulnerableType].append(caller)
        return self.vulnerableCheckResult

    # 检测出现跟相应的值  如果同一个 vulnerableType 会出现覆盖的情况 !!!!!!!!!!!!! 
    def vulnerableWithCodeChecks(self, vulneras):
        self.vulnerableWithCodeCheckResult = {}
        for vulnera in vulneras:
            vulnerableType = vulnera["vulnerableType"]
            className = vulnera["className"]
            methodName = vulnera["methodName"]
            descriptor = vulnera["descriptor"]
            registersIndex = int(vulnera["registersIndex"])
            structural_analysis_results = self.dx.find_methods(classname=className,methodname=methodName)
            caller = []
            for registers, appearance  in data_flow_analysis(structural_analysis_results, self.dx):
                if registersIndex < len(registers):# 取不到值的丢弃 ??? 
                    registerValue = get_register_value(registersIndex, registers)
                    if "0x80000801" == vulnerableType:
                        if registerValue == "\"AES\"" or "AES/ECB/" in registerValue:
                            caller.append([appearance, get_register_value(registersIndex, registers)])
                        elif "DES" in registerValue and "DESede" != registerValue:
                            caller.append([appearance, get_register_value(registersIndex, registers)])
                    elif "0x80001501" == vulnerableType:
                        if 1 == registerValue:
                            caller.append([appearance, get_register_value(registersIndex, registers)])
                    elif "0x80000a01" == vulnerableType:
                        if 1 == registerValue or 2 == registerValue:
                            caller.append([appearance, get_register_value(registersIndex, registers)])
                    else:
                        caller.append([appearance, get_register_value(registersIndex, registers)])
            self.vulnerableWithCodeCheckResult[vulnerableType] = caller
            return self.vulnerableWithCodeCheckResult

    # 检测出现的字符串 
    def vulnerableStringChecks(self, vulneras):
        self.vulnerableStringCheckResult = {}
        for vulnera in vulneras:
            vulnerableType = vulnera["vulnerableType"]
            regStr = vulnera["regStr"]
            str_found = self.dx.find_strings(regStr)
            strings = []
            # for s in str_found:
            #     strings.append(s.get_orig_value())# for ca, ecMeth in s.get_xref_from(): "{}->{}{}".format(ca.name, ecMeth.get_name(), ecMeth.get_descriptor().replace(" ", ""))
            for s in str_found:
                # strings.append(s.get_orig_value())# for ca, ecMeth in s.get_xref_from(): "{}->{}{}".format(ca.name, ecMeth.get_name(), ecMeth.get_descriptor().replace(" ", ""))
                for ca, ecMeth in s.get_xref_from():
                    strings.append([s.get_orig_value(),"{}->{}{}".format(ca.name, ecMeth.get_name(), ecMeth.get_descriptor().replace(" ", ""))])
            self.vulnerableStringCheckResult[vulnerableType] = strings
        
        return self.vulnerableStringCheckResult


    def check_permissions(self, perm):
        # cwd = os.path.dirname(os.path.realpath(__file__))  # 
        # path = os.path.join(cwd, "permissions.txt")
        # perm = Utils.loadRiskPermission(path)
        # perm = self.load_risk_permission()
        print("   [-]Permissions")
        if not isinstance(perm, list):
            perm = a.load_risk_permission()
        
        for permission in self.a.get_permissions():
            if None != perm and 0 < len(perm):
                if str(permission) in perm and str(permission) not in self.permissions:
                    self.permissions.append(str(permission))
        return self.permissions

    def load_risk_permission(self):
        cwd = os.path.dirname(os.path.realpath(__file__))  # 
        path = os.path.join(cwd, "permissions.txt")
        per = Utils.loadRiskPermission(path)
        return per

    def load_white_list(self):
        # 从文件中读取白名单 !!! 
        cwd = os.path.dirname(os.path.realpath(__file__))
        path = os.path.join(cwd, "whitelist.txt")
        self.whiteList = Utils.loadConfFile(path)
        return self.whiteList

    def check_apperance(self, class_name, method_name, descriptor=""):
        results = []
        method_found = self.dx.find_methods(classname=class_name, methodname=method_name)# 找到多条 ???????? 
        for meth in method_found:
            xref_from = meth.get_xref_from()
            for x in xref_from:
                ca, ecMeth, idx = x
                # 增加白名单过滤  全局过滤
                if any(ca.name.startswith(item) for item in self.whiteList):
                    continue
                results.append("{}->{} {}{}".format(ca.name, ecMeth.get_access_flags_string(), ecMeth.get_name(), ecMeth.get_descriptor().replace(" ", "")))
        return results
    
    def check_params(self, class_name, method_name, register_index, vulnerable_type, descriptor=""):
        structural_analysis_results = self.dx.find_methods(classname=class_name,methodname=method_name)
        caller = []
        for registers, appearance  in data_flow_analysis(structural_analysis_results, self.dx):
            if register_index < len(registers):
                register_value = get_register_value(register_index, registers)
                # caller.append([appearance, get_register_value(register_index, registers)])
                if any(appearance.startswith(item) for item in self.whiteList):
                    continue
                
                if "0x80000801" == vulnerable_type:
                    if register_value == "\"AES\"" or "AES/ECB/" in register_value:
                        caller.append([appearance, get_register_value(register_index, registers)])
                    elif "DES" in register_value and "DESede" != register_value:
                        caller.append([appearance, get_register_value(register_index, registers)])
                elif "0x80001501" == vulnerable_type:
                    if 1 == register_value:
                        caller.append([appearance, get_register_value(register_index, registers)])
                elif "0x80000a01" == vulnerable_type:
                    if 1 == register_value or 2 == register_value:
                        caller.append([appearance, get_register_value(register_index, registers)])
                else:
                    caller.append([appearance, get_register_value(register_index, registers)])
        return caller
    
    def format_output(self, ca, ecMeth):
        return "{}->{} {}{}".format(ca.name, ecMeth.get_access_flags_string(), ecMeth.get_name(), ecMeth.get_descriptor().replace(" ", ""))
    
    def check_strings(self, reg_string):
        str_found = self.dx.find_strings(reg_string)
        results = []
        for s in str_found:
            for ca, ecMeth in s.get_xref_from():
                if any(ca.name.startswith(item) for item in self.whiteList):
                    continue
                results.append([s.get_orig_value(),"{}->{} {}{}".format(ca.name, ecMeth.get_access_flags_string(), ecMeth.get_name(), ecMeth.get_descriptor().replace(" ", ""))])
        return results

    def load_vulnerable_feature(self):
        conf = None
        try:
            # with open("D:/Works/接口/test", "r", encoding='utf-8') as fp:
            with open("D:/Works/docs/接口/android_feater.feater", "r", encoding='utf-8') as fp:
                # config = json.loads(fp.read()) 
                config = load(fp)
        except Exception as e:
            print(e)
            return conf

        if isinstance(config, str):
            conf = json.loads(config)
        elif isinstance(config, list):
            conf = config
        else:
            conf = None
        
        return conf

    def load_config_check(self, conf=""):
        # current_file = "D:/Works/apk/qq_v5.3.1.apk"
        # config = get_config(current_file)
        
        # try:
        #     with open("D:/Works/接口/test", "r", encoding='utf-8') as fp:
        #         config = json.loads(fp.read())
        # except Exception as e:
        #     print(e)
        #     return

        # if isinstance(config, str):
        #     conf = json.loads(config)
        # elif isinstance(config, list):
        #     conf = config
        # else:
        #     conf = None
        # conf = self.load_vulnerable_feature()
        
        if None != conf:
            for item in conf:
                nne_id = item.get("nneId", None)
                t = item.get("type", None)
                feature = item.get("feature", None)
                flaw_report_info = item.get("flawReportInfo", None)
                if None != t:
                    if 1 == t:
                        if None != feature:
                            for v in feature: 
                                scan_type = v.get("scanType", None)
                                vulnerable_type = v.get("vulnerableType", None)
                                class_name = v.get("className", "")
                                method_name = v.get("methodName", "")
                                descriptor = v.get("descriptor", "")
                                if None != vulnerable_type:
                                    self.vulnerableCheckResult[vulnerable_type] = self.check_apperance(class_name, method_name)
                    elif 3 == t:
                        if None != feature:
                            for v in feature: 
                                scan_type = v.get("scanType", None)
                                vulnerable_type = v.get("vulnerableType", None)
                                class_name = v.get("className", "")
                                method_name = v.get("methodName", "")
                                descriptor = v.get("descriptor", "")
                                register_index = v.get("registersIndex")
                                if None != vulnerable_type:
                                    self.vulnerableWithCodeCheckResult[vulnerable_type] = self.check_params(class_name, method_name, int(register_index), vulnerable_type)
                    elif 5 == t:
                        if None != feature:
                            for v in feature:
                                scan_type = v.get("scanType", None)
                                vulnerable_type = v.get("vulnerableType", None)
                                reg_str = v.get("regStr", None)
                                if None != vulnerable_type:
                                    self.vulnerableStringCheckResult[vulnerable_type] = self.check_strings(reg_str)
        

    def checkVulnerables(self):
        cwd = os.path.dirname(os.path.realpath(__file__))  # 
        path = os.path.join(cwd, "vulnerableConfig.json")
        # path = os.path.join(cwd, "vulnerableConfigTmp.json")
        vulneras = Utils.readJsonFile(path)
        # vulnerableCheck = vulneras["vulnerableCheck"]
        # vulnerableWithCodeCheck = vulneras["vulnerableWithCodeCheck"]
        # vulnerableStrings = vulneras["vulnerableStrings"]
        vulnerableCheck = vulneras.get("vulnerableCheck", None)
        vulnerableWithCodeCheck = vulneras.get("vulnerableWithCodeCheck", None)
        vulnerableStrings = vulneras.get("vulnerableStrings", None)
        if vulnerableCheck:
            self.vulnerableChecks(vulnerableCheck)
        if vulnerableWithCodeCheck:
            self.vulnerableWithCodeChecks(vulnerableWithCodeCheck)
        if vulnerableStrings:
            self.vulnerableStringChecks(vulnerableStrings)



def convert_dex_to_canonical(dex_name) :
    """
        @param dex_name : a dex name, for instance "Lcom/name/test"
    
        @rtype : a dotted string, for instance "com.name.test"
    """
    final_name = ''
    if re.match('^\[?L[a-zA-Z]+(?:\/[a-zA-Z]+)*(.)*;$', dex_name) :
        global_part = dex_name[1:-1].split('/')
        final_part = global_part[:-1]
        last_part = global_part[-1].split('$')[0]
        final_part.append(str(last_part))
        final_name = '.'.join(str(i) for i in final_part)
    else :
        print("[!] Conversion to canonical dotted name failed : \"" + dex_name + "\" is not a valid library dex name")
    return final_name

def convert_canonical_to_dex(canonical_name) :
    return 'L' + canonical_name.replace('..', '.').replace('.', '/') + ';'

