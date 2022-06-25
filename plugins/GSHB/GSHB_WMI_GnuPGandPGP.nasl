###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_GnuPGandPGP.nasl 10949 2018-08-14 09:36:21Z emoss $
#
# Get GnuPG and PGP Version and User they have an pubring (win)
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
  script_oid("1.3.6.1.4.1.25623.1.0.96045");
  script_version("$Revision: 10949 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Get GnuPG and PGP Version and User they have an pubring (win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"Get GnuPG and PGP Version and User they have an pubring (win)");

  exit(0);
}

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
  set_kb_item(name:"WMI/GnuPGVersion", value:"error");
  set_kb_item(name:"WMI/PGPVersion", value:"error");
  set_kb_item(name:"WMI/GnuPGpubringsUser", value:"error");
  set_kb_item(name:"WMI/PGPpubringsUser", value:"error");
  set_kb_item(name:"WMI/PGP/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);
handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);


if(!handle || !handlereg){
  set_kb_item(name:"WMI/GnuPGVersion", value:"error");
  set_kb_item(name:"WMI/PGPVersion", value:"error");
  set_kb_item(name:"WMI/GnuPGpubringsUser", value:"error");
  set_kb_item(name:"WMI/PGPpubringsUser", value:"error");
  set_kb_item(name:"WMI/PGP/log", value:"wmi_connect: WMI Connect failed.");
  wmi_close(wmi_handle:handle);
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

GNUPGKEY = wmi_reg_enum_value(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GnuPG");

if (GNUPGKEY)
{
  query1 = 'select Name, FileSize from CIM_DataFile WHERE FileName = "pubring" AND Extension LIKE "gpg"';
  gnupgvers = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GnuPG", key_name:"DisplayVersion");
  gnupgpubrings = wmi_query(wmi_handle:handle, query:query1);
  if (gnupgpubrings)
  {
    gnupgpubrings = split(gnupgpubrings, sep:'\n', keep:0);
    for(g=1; g<max_index(gnupgpubrings); g++)
    {
       if("FileSize|Name" >< gnupgpubrings[g]){
         continue;
       }
       path = split(gnupgpubrings[g], sep:"|", keep:0);
       if(path !=NULL)
       {
       if(path[0] > 0)
       {
         name = split(path[1], sep:"\", keep:0);
         if(OSVER >= 6)
         {
           b = max_index(name) -5 ;
         }
         else
         {
           b = max_index(name) -4 ;
         }
         gnupgpubringsuser = gnupgpubringsuser + "Username: " + name[b] + ", Pubringgröße: " + path[0] + " Byte ;";
       }
       }
    }
  }
  else
  {
    gnupgpubringsuser = "none";
  }
}else
{
gnupgvers = "none";
gnupgpubringsuser = "none";
}

query2 = 'select Version from CIM_DataFile WHERE FileName = "pgpdesk" AND Extension LIKE "exe"';
pgpversion =  wmi_query(wmi_handle:handle, query:query2);

if (pgpversion)
{
  pgpversion = split(pgpversion, sep:"|", keep:0);
  pgpversion = ereg_replace(pattern:'\n', string:pgpversion[2], replace:'');
  query3 = 'select Name, FileSize from CIM_DataFile WHERE FileName = "pubring" AND Extension LIKE "pkr"';
  pgppubrings = wmi_query(wmi_handle:handle, query:query3);

  if (pgppubrings)
  {
    pgppubrings = split(pgppubrings, sep:'\n', keep:0);
    for(i=1; i<max_index(pgppubrings); i++)
    {
       if("FileSize|Name" >< pgppubrings[i]){
         continue;
       }
       path = split(pgppubrings[i], sep:"|", keep:0);
       if(path !=NULL)
       {
       if(path[0] > 0)
       {
         name = split(path[1], sep:"\", keep:0);
                  if(OSVER >= 6)
         {
           a = max_index(name) -5 ;
         }
         else
         {
           a = max_index(name) -4 ;
         }
         pgppubringsuser = pgppubringsuser + "Username: " + name[a] + ", Pubringgröße: " + path[0] + " Byte ;";
       }

       }
    }
  }
  else
  {
    pgppubringsuser = "none";
  }
}else
{
  pgppubringsuser = "none";
  pgpversion = "none";
}

if(!pgppubringsuser) pgppubringsuser = "none";
if(!gnupgpubringsuser) gnupgpubringsuser = "none";

set_kb_item(name:"WMI/GnuPGVersion", value:gnupgvers);
set_kb_item(name:"WMI/PGPVersion", value:pgpversion);
set_kb_item(name:"WMI/GnuPGpubringsUser", value:gnupgpubringsuser);
set_kb_item(name:"WMI/PGPpubringsUser", value:pgppubringsuser);

wmi_close(wmi_handle:handle);
wmi_close(wmi_handle:handlereg);

exit(0);
