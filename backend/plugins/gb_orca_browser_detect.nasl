###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orca_browser_detect.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# Orca Browser Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800900");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11015 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-09-08 18:25:53 +0200 (Tue, 08 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Orca Browser Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the installed version of Orca Browser
  and sets the result in KB.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Orca Browser Version Detection";

function OrcaGetVersion(file)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:file);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:file);

  name   =  kb_smb_name();
  login  =  kb_smb_login();
  pass   =  kb_smb_password();
  domain =  kb_smb_domain();
  port   =  kb_smb_transport();

  soc = open_sock_tcp(port);
  if(!soc){
    return NULL;
  }

  r = smb_session_request(soc:soc, remote:name);
  if(!r)
  {
    close(soc);
    return NULL;
  }

  prot = smb_neg_prot(soc:soc);
  if(!prot)
  {
    close(soc);
    return NULL;
  }

  r = smb_session_setup(soc:soc, login:login, password:pass,
                        domain:domain, prot:prot);
  if(!r)
  {
    close(soc);
    return NULL;
  }

  uid = session_extract_uid(reply:r);
  if(!uid)
  {
    close(soc);
    return NULL;
  }

  r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
  if(!r)
  {
    close(soc);
    return NULL;
  }

  tid = tconx_extract_tid(reply:r);
  if(!tid)
  {
    close(soc);
    return NULL;
  }

  fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
  if(!fid)
  {
    close(soc);
    return NULL;
  }

  ver = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, offset:250000);
  close(soc);

  return ver;
}


if(!get_kb_item("SMB/WindowsVersion"))
{
  exit(0);
}

orca_key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OrcaBrowser";
orcaName = registry_get_sz(key:orca_key + item, item:"DisplayName");

if("Orca Browser" >< orcaName)
{
  orcaPath = registry_get_sz(key:orca_key + item, item:"UninstallString");

  if(orcaPath =~ '(^\")([A-Z]:.*)')
  {
    orcaPath = eregmatch(pattern:'\"(.*)\"', string:orcaPath);
    orcaPath = orcaPath[1] - "uninst.exe" + "orca.exe";
  }
  else
   orcaPath = orcaPath - "uninst.exe" + "orca.exe";

  orcaVer = OrcaGetVersion(file:orcaPath);
  if(!isnull(orcaVer))
  {
    set_kb_item(name:"OrcaBrowser/Ver", value:orcaVer);
    log_message(data:"Orca Browser version " + orcaVer + " running at location "
                      + orcaPath + " was detected on the host");

    cpe = build_cpe(value:orcaVer, exp:"^([0-9]\.[0-9])", base:"cpe:/a:orcabrowser:orca_browser:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  }
}
