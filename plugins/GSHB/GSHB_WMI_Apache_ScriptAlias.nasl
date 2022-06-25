###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_Apache_ScriptAlias.nasl 11369 2018-09-13 11:30:29Z cfischer $
#
# List Files in Apache Script Alias Directories over WMI (win)
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.96023");
  script_version("$Revision: 11369 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 13:30:29 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("List Files in  Apache Script Alias Directories over WMI (win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_Apache.nasl", "GSHB/GSHB_Read_Apache_Config.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/Apache/RootPath");

  script_tag(name:"summary", value:"List Files in Apache Script Alias Directories over WMI");

  exit(0);
}

include("wmi_file.inc");
include("smb_nt.inc");

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd = kb_smb_password();


OSVER = get_kb_item("WMI/WMI_OSVER");

if(!OSVER || OSVER >< "none"){
    set_kb_item(name:"WMI/Apache/CGIFileList", value:"error");
    set_kb_item(name:"WMI/Apache/CGIFileList/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);

if(!handle){
  set_kb_item(name:"WMI/Apache/CGIFileList", value:"error");
  set_kb_item(name:"WMI/Apache/CGIFileList/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  exit(0);
}

ROOTPATH = get_kb_item("WMI/Apache/RootPath");

if(ROOTPATH >< "None"){
  set_kb_item(name:"WMI/Apache/CGIFileList", value:"None");
  log_message(port:0, proto: "IT-Grundschutz", data:string("No Apache Installed") + string("\n"));
  wmi_close(wmi_handle:handle);
  exit(0);
}


DOCROOT = get_kb_item("GSHB/Apache/DocumentRoot");
DOCROOT = ereg_replace(pattern:'/',replace:'\\\\', string:DOCROOT);
DOCROOT = split(DOCROOT, sep:'|', string:DOCROOT);
APROOT = ROOTPATH;
APROOT = ereg_replace(pattern:'\\\\', replace:'/', string:ROOTPATH);
APROOT = tolower(APROOT);
APDOC = get_kb_item("GSHB/Apache/DocumentRoot");
APDOC = tolower(APDOC);
APCGIDIR = get_kb_item("GSHB/Apache/ScriptAlias");
APCGIDIR = tolower(APCGIDIR);



if (!APCGIDIR){
    set_kb_item(name:"WMI/Apache/CGIFileList", value:"inapplicable");
    log_message(port:0, proto: "IT-Grundschutz", data:string("No CGI Alias given"));
    wmi_close(wmi_handle:handle);
exit(0);
}


APCGIDIR = split(APCGIDIR, sep:'|', keep:0);
APDOC = split(APDOC, sep:'|', keep:0);

for(p=0; p<max_index(APCGIDIR); p++)
{
  if (!APCGIDIR[p]) continue;
  for(a=0; a<max_index(APDOC); a++)
  {
    if (!APDOC[a]) continue;
    if(APDOC[a] !~ "^[A-Za-z]:") APDOCPATH = APROOT + APDOC[a];
    else APDOCPATH = APDOC[a];

    if(APCGIDIR[p] !~ "^[A-Za-z]:")
    {
      if(APCGIDIR[p] !~ "^/") APCGIDIRPATH = APDOCPATH + '/' + APCGIDIR[p];
      else APCGIDIRPATH = APDOCPATH + APCGIDIR[p];
    }
    else APCGIDIRPATH = APCGIDIR[p];
    if (APDOCPATH >< APCGIDIRPATH)
    {
    CGIDIRROOT = "FALSE";
    }
    else
    {
    CGIDIRROOT = "TRUE";
    }
    if ("FALSE" >< CGIDIRROOT)
    {
      if(APCGIDIRPATH !~ "[/]$") APCGIDIRPATH = APCGIDIRPATH + '/';
      CGIDIRROOTSUM = CGIDIRROOTSUM + APCGIDIRPATH + ';';
    }
  }
}
if (!CGIDIRROOTSUM) CGIDIRROOTSUM = "FALSE";
if ("FALSE" >!< CGIDIRROOTSUM)
{

  CGIDIR = ereg_replace(pattern:'/;',replace:';', string:CGIDIRROOTSUM);
  CGIDIR = ereg_replace(pattern:'/',replace:'\\\\', string:CGIDIR);
  CGIDIR = split(CGIDIR, sep:';', keep:0);

  for (c=0; c<max_index(CGIDIR); c++)
  {
    if (!CGIDIR[c]) continue;
    CGIDIRCHECK = ereg_replace(pattern:'^[A-Za-z]:',replace:'', string:CGIDIR[c]);
    CGIDIRCHECK = CGIDIRCHECK + '\\\\';
    CGIDIRZERO = ereg_replace(pattern:'^[A-Za-z]:',replace:'', string:CGIDIR[0]);
    CGIDIRZERO = CGIDIRZERO + '\\\\';

    CHECKCGIDIREXIST = wmi_file_check_dir_exists(handle:handle, dirPath:CGIDIR[c]);

    if (CHECKCGIDIREXIST == 1)
    {
      CHECKCGIDIRPATHSUM = CHECKCGIDIRPATHSUM + CGIDIR[c] + ';';
      if(c == 0)
      {
        CGIFILELIST = wmi_file_filelist(handle:handle, dirPath:CGIDIRCHECK);
        if(CGIFILELIST)
        {
          foreach CGIFILE( CGIFILELIST )
          {
            CGIFILES += CGIFILE + '\n';
          }
          CGIFILES += '\n';
        }
        else
        {
          CGIFILES += '\n\n';
        }
      }
      else if(CGIDIRZERO >!< CGIDIRCHECK)
      {
        CGIFILELIST = wmi_file_filelist(handle:handle, dirPath:CGIDIRCHECK);
        if(CGIFILELIST)
        {
          foreach CGIFILE( CGIFILELIST )
          {
            CGIFILES += CGIFILE + '\n';
          }
          CGIFILES += '\n';
        }
        else
        {
          CGIFILES += '\n\n';
        }
      }
    }
  }
  if (!CHECKCGIDIRPATHSUM) CHECKCGIDIRPATHSUM ="None";
}
if (!CGIFILES) CGIFILES = "None";
set_kb_item(name:"WMI/Apache/CGIFileList", value:CGIFILES);
set_kb_item(name:"WMI/Apache/CGIinDOCPath", value:CGIDIRROOTSUM);
set_kb_item(name:"WMI/Apache/CGIinDOCPathSum", value:CHECKCGIDIRPATHSUM);

wmi_close(wmi_handle:handle);

exit(0);

