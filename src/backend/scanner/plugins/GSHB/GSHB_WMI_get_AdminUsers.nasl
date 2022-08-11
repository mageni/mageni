###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_get_AdminUsers.nasl 10949 2018-08-14 09:36:21Z emoss $
#
# Get all Windows Admin Users and Groups over WMI (win)
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
  script_oid("1.3.6.1.4.1.25623.1.0.96030");
  script_version("$Revision: 10949 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Get all Windows Admin Users and Groups over WMI (win)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"Get all Windows non System Services
  and Eventlog Servicestate over WMI.");

  exit(0);
}

include("wmi_user.inc");
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
    set_kb_item(name:"WMI/LocalWindowsAdminUsers", value:"error");
    set_kb_item(name:"WMI/LocalWindowsAdminUsers/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);

if(!handle){
    set_kb_item(name:"WMI/LocalWindowsAdminUsers", value:"error");
    set_kb_item(name:"WMI/LocalWindowsAdminUsers/log", value:"wmi_connect: WMI Connect failed.");
    wmi_close(wmi_handle:handle);
    exit(0);
}

LOCUSRGRP = wmi_user_groupuser(handle:handle);
LOCUSRGRP = tolower(LOCUSRGRP);
LOCUSRGRP = split(LOCUSRGRP, sep:'\n', keep:0);
LOCUSRS = "";

for(i=1; i<max_index(LOCUSRGRP); i++)
  {
    LOCUSRGRPinf = split(LOCUSRGRP[i], sep:"|", keep:0);
    LocGrpLst = eregmatch(pattern:'name="[^\"]+', string:LOCUSRGRPinf[0]);
    LocGrpLst[0] = ereg_replace(pattern:'name="', string:LocGrpLst[0], replace:"");
    if("admin" >< LocGrpLst[0])
    {
        LocUsrLst = eregmatch(pattern:'name="[^\"]+', string:LOCUSRGRPinf[1]);
        LocUsrLst[0] = ereg_replace(pattern:'name="', string:LocUsrLst[0], replace:"");

        if (LocUsrLst[0] >!< LOCUSRS)
        {
           LOCUSRS = LOCUSRS + LocUsrLst[0] + '|';
        }
     }
  }

QLOCUSRS =split(LOCUSRS, sep:"|", keep:0);

for(o=1; o<max_index(LOCUSRGRP); o++)
{
    OLOCUSRGRPinf = split(LOCUSRGRP[o], sep:"|", keep:0);
    OLocGrpLst = eregmatch(pattern:'name="[^\"]+', string:OLOCUSRGRPinf[0]);
    OLocGrpLst[0] = ereg_replace(pattern:'name="', string:OLocGrpLst[0], replace:"");
    for(Q=1; Q<max_index(QLOCUSRS); Q++)
    {
        if(QLOCUSRS[Q] >< OLocGrpLst[0])
        {
            OLocUsrLst = eregmatch(pattern:'name="[^\"]+', string:OLOCUSRGRPinf[1]);
            OLocUsrLst[0] = ereg_replace(pattern:'name="', string:OLocUsrLst[0], replace:"");
            if (OLocUsrLst[0] >!< LOCUSRS )
            {
               LOCUSRS = LOCUSRS + OLocUsrLst[0] + '|';
            }
         }
    }
}


set_kb_item(name:"WMI/LocalWindowsAdminUsers", value:LOCUSRS);
wmi_close(wmi_handle:handle);
exit(0);
