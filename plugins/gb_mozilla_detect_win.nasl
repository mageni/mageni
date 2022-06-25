###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_detect_win.nasl 10888 2018-08-10 12:08:02Z cfischer $
#
# Mozilla Version Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800883");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10888 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:08:02 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"registry");
  script_name("Mozilla Version Detection (Windows)");


  script_tag(name:"summary", value:"Detects the installed version of Mozilla on Windows.

The script logs in via smb, searches for Mozilla in the registry and gets
the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

function mozillaGetVersion(file, share)
{
  mshare = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:file);
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

  r = smb_tconx(soc:soc, name:name, uid:uid, share:mshare);
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
  ver = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, verstr:"prod");
  close(soc);

  return ver;
}

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if("x86" >< osArch){
  path = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Mozilla.exe";
}

else if("x64" >< osArch){
  path = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\Mozilla.exe";
}

if(!registry_key_exists(key:path)){
  exit(0);
}

mozillaName = registry_get_sz(key:path, item:"Path");
if("mozilla.org" >< mozillaName)
{
  mozillaPath = mozillaName + "\mozilla.exe";
  mozillaVer = mozillaGetVersion(file:mozillaPath);

  if(!isnull(mozillaVer))
  {
    set_kb_item(name:"Mozilla/Win/Ver", value:mozillaVer);
    set_kb_item( name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed", value:TRUE );

    cpe = build_cpe(value:mozillaVer, exp:"^([0-9.]+)", base:"cpe:/a:mozilla:mozilla:");
    if(isnull(cpe))
      cpe = "cpe:/a:mozilla:mozilla";

    register_product(cpe: cpe, location: path);
    log_message(data: build_detection_report(app: "Mozilla Browser",
                                             version: mozillaVer,
                                             install: path,
                                                 cpe: cpe,
                                           concluded: mozillaVer));


  }
}
