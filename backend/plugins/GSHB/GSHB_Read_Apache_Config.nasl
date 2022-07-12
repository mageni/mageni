###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_Read_Apache_Config.nasl 13295 2019-01-25 13:33:05Z cfischer $
#
# Reading Apache Config (Windows)
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96020");
  script_version("$Revision: 13295 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-25 14:33:05 +0100 (Fri, 25 Jan 2019) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Reading Apache Config (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_Apache.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"Reading Apache Config");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("GSHB_read_file.inc");
include("smb_nt.inc");

OSVER = get_kb_item("WMI/WMI_OSVER");

if(!OSVER || OSVER >< "none"){
  set_kb_item(name:"GSHB/ApacheConfig", value:"error");
  set_kb_item(name:"GSHB/ApacheConfig/log", value:string("No access to SMB host.\nFirewall is activated or there is not a Windows system."));
  exit(0);
}

path = get_kb_item("WMI/Apache/RootPath");

if("None" >< path){
  set_kb_item(name:"GSHB/ApacheConfig", value:"None");
  log_message(port:0, proto:"IT-Grundschutz", data:string("No Apache Installed") + string("\n"));
  exit(0);
}

path = split(path, sep:":", keep:FALSE);
share = path[0] + "$";
file = path[1] + "conf\httpd.conf";
config = GSHB_read_file(share: share, file: file, offset: 0);

if (!config){
#   AspEnableParentPaths = "error";
   log_message(port:0, proto:"IT-Grundschutz", data:"Cannot access/open the Apache config file.");
   set_kb_item(name:"GSHB/ApacheConfig", value:"error");
} else {
   DocumentRoot = egrep(pattern:'^ *DocumentRoot \".*', string:config);
   DocumentRoot = ereg_replace(pattern:' *DocumentRoot *"',replace:'', string:DocumentRoot);
   DocumentRoot = ereg_replace(pattern:'" *\r\n',replace:'|', string:DocumentRoot);
   ScriptAlias = egrep(pattern:'^ *ScriptAlias \\.*', string:config);
   ScriptAlias = ereg_replace(pattern:' *ScriptAlias */[_#+|<>@!$%&/()=a-zA-Z0-9-]*/ *"',replace:'', string:ScriptAlias);
   ScriptAlias = ereg_replace(pattern:'" *\r\n',replace:'|', string:ScriptAlias);
   Includes = egrep(pattern:'^ *Include .*', string:config);
   Includes = ereg_replace(pattern:'\r\n',replace:'|', string:Includes);
   Includes = ereg_replace(pattern:'Include ',replace:'', string:Includes);
   CustomLog = egrep(pattern:'^ *CustomLog *', string:config);
   CustomLog = ereg_replace(pattern:'" *[_#+|<>@!$%&/()=a-zA-Z0-9-]*\r\n',replace:'|', string:CustomLog);
   CustomLog = ereg_replace(pattern:' *CustomLog *"',replace:'', string:CustomLog);
   ErrorLog = egrep(pattern:'^ *ErrorLog *', string:config);
   ErrorLog = ereg_replace(pattern:'" *[_#+|<>@!$%&/()=a-zA-Z0-9-]*\r\n',replace:'|', string:ErrorLog);
   ErrorLog = ereg_replace(pattern:' *ErrorLog *"',replace:'', string:ErrorLog);
   AllowFrom = egrep(pattern:'^ *Allow from *', string:config);
   AllowFrom = ereg_replace(pattern:' *Allow',replace:'Allow', string:AllowFrom);
   AllowFrom = ereg_replace(pattern:' *\r\n',replace:'|', string:AllowFrom);

   LMCGI = egrep(pattern:'^ *LoadModule *cgi_module *modules/mod_cgi.so', string:config);

   LMINC = egrep(pattern:'^ *LoadModule *include_module *modules/mod_include.so', string:config);

   LMISAPI = egrep(pattern:'^ *LoadModule *isapi_module *modules/mod_isapi.so', string:config);

   LMPERL = egrep(pattern:'^ *LoadModule *perl_module *modules/libperl.so', string:config);

   LMPHP = egrep(pattern:'^ *LoadModule *perl_module *modules/mod_php.so', string:config);

   LMPHP3 = egrep(pattern:'^ *LoadModule *perl_module *modules/libphp3.so', string:config);

   LMPHP4 = egrep(pattern:'^ *LoadModule *perl_module *modules/libphp4.so', string:config);

   LMJK = egrep(pattern:'^ *LoadModule *perl_module *modules/mod_jk.so', string:config);
}

IncludesSplit = split (Includes, sep:'|', keep:0);

if(IncludesSplit[1]){

for(j=0; j<max_index(IncludesSplit); j++) {

  LogIncPath = get_kb_item("WMI/Apache/RootPath");
  LogIncPath = split(LogIncPath, sep:":", keep:0);
  LogIncShare = LogIncPath[0] + "$";
  LogIncFile = ereg_replace(pattern:'/',replace:'\\', string:IncludesSplit[j]);
  LogIncFile = LogIncPath[1] + LogIncFile;

  val01 = GSHB_read_file(share: LogIncShare, file: LogIncFile, offset: 0);

  CustomLogInc = egrep(pattern:'^ *CustomLog *', string:val01);
  CustomLogInc = ereg_replace(pattern:'" *[_#+|<>@!$%&/()=a-zA-Z0-9-]*\r\n',replace:'|', string:CustomLogInc);
  CustomLogInc = ereg_replace(pattern:' *CustomLog *"',replace:'', string:CustomLogInc);
  if (CustomLogInc >!< '')
    CustomLog += CustomLogInc + '|';

  ErrorLogInc = egrep(pattern:'^ *ErrorLog *', string:val01);
  ErrorLogInc = ereg_replace(pattern:'" *[_#+|<>@!$%&/()=a-zA-Z0-9-]*\r\n',replace:'|', string:ErrorLogInc);
  ErrorLogInc = ereg_replace(pattern:' *ErrorLog *"',replace:'', string:ErrorLogInc);
  if (ErrorLogInc >!< '')
    ErrorLog += ErrorLogInc + '|';

  ScriptAliasInc = egrep(pattern:'^ *ScriptAlias \\.*', string:val01);
  ScriptAliasInc = ereg_replace(pattern:' *ScriptAlias */[_#+|<>@!$%&/()=a-zA-Z0-9-]*/ *"',replace:"", string:ScriptAliasInc);
  ScriptAliasInc = ereg_replace(pattern:'" *\r\n',replace:'|', string:ScriptAliasInc);
  if (ScriptAliasInc >!< '')
    ScriptAlias += ScriptAliasInc + '|';

  DocumentRootInc = egrep(pattern:'^ *DocumentRoot \".*', string:val01);
  DocumentRootInc = ereg_replace(pattern:' *DocumentRoot *"',replace:'', string:DocumentRootInc);
  DocumentRootInc = ereg_replace(pattern:'" *\r\n',replace:'|', string:DocumentRootInc);
  if (DocumentRootInc >!< '')
    DocumentRoot += DocumentRootInc + '|';

  AllowFromInc = egrep(pattern:'^ *Allow from *', string:val01);
  AllowFromInc = ereg_replace(pattern:' *Allow',replace:'Allow', string:AllowFromInc);
  AllowFromInc = ereg_replace(pattern:' *\r\n',replace:'|', string:AllowFromInc);
  if (AllowFromInc >!< '')
    AllowFrom += AllowFromInc + '|';

  LMCGIInc = egrep(pattern:'^ *LoadModule *cgi_module *modules/mod_cgi.so', string:val01);
  if (LMCGIInc >!< '')
    LMCGI += LMCGIInc + '|';

  LMINCInc = egrep(pattern:'^ *LoadModule *include_module *modules/mod_include.so', string:val01);
  if (LMCGIInc >!< '')
    LMINC += LMINCInc + '|';

  LMISAPIInc = egrep(pattern:'^ *LoadModule *isapi_module *modules/mod_isapi.so', string:val01);
  if (LMISAPIInc >!< '')
    LMISAPI += LMISAPIInc + '|';

  LMPERLInc = egrep(pattern:'^ *LoadModule *perl_module *modules/libperl.so', string:val01);
  if (LMPERLInc >!< '')
    LMPERL += LMPERLInc + '|';

  LMPHPInc = egrep(pattern:'^ *LoadModule *perl_module *modules/mod_php.so', string:val01);
  if (LMPHPInc >!< '')
    LMPHP += LMPHPInc + '|';

  LMPHP3Inc = egrep(pattern:'^ *LoadModule *perl_module *modules/libphp3.so', string:val01);
  if (LMPHP3Inc >!< '')
    LMPHP3 += LMPHP3Inc + '|';

  LMPHP4Inc = egrep(pattern:'^ *LoadModule *perl_module *modules/libphp4.so', string:val01);
  if (LMPHP4Inc >!< '')
    LMPHP4 += LMPHP4Inc + '|';

  LMJKInc = egrep(pattern:'^ *LoadModule *perl_module *modules/mod_jk.so', string:val01);
  if (LMJKInc >!< '')
    LMJK += LMJKInc + '|';
  }
}

if (!LMCGI) LMCGI = "None";
if (!LMINC) LMINC = "None";
if (!LMISAPI) LMISAPI = "None";
if (!LMPERL) LMPERL = "None";
if (!LMPHP) LMPHP = "None";
if (!LMPHP3) LMPHP3 = "None";
if (!LMPHP4) LMPHP4 = "None";
if (!LMJK) LMJK = "None";

set_kb_item(name:"GSHB/Apache/LoadModul_LMCGI", value:LMCGI);
set_kb_item(name:"GSHB/Apache/LoadModul_LMINC", value:LMINC);
set_kb_item(name:"GSHB/Apache/LoadModul_LMISAPI", value:LMISAPI);
set_kb_item(name:"GSHB/Apache/LoadModul_LMPERL", value:LMPERL);
set_kb_item(name:"GSHB/Apache/LoadModul_LMPHP", value:LMPHP);
set_kb_item(name:"GSHB/Apache/LoadModul_LMPHP3", value:LMPHP3);
set_kb_item(name:"GSHB/Apache/LoadModul_LMPHP4", value:LMPHP4);
set_kb_item(name:"GSHB/Apache/LoadModul_LMJK", value:LMJK);

set_kb_item(name:"GSHB/Apache/DocumentRoot", value:DocumentRoot);
set_kb_item(name:"GSHB/Apache/ScriptAlias", value:ScriptAlias);
set_kb_item(name:"GSHB/Apache/ErrorLog", value:ErrorLog);
set_kb_item(name:"GSHB/Apache/CustomLog", value:CustomLog);
set_kb_item(name:"GSHB/Apache/AllowFrom", value:AllowFrom);
set_kb_item(name:"GSHB/Apache/Includes", value:Includes);
exit(0);