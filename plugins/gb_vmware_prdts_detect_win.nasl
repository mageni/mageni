###############################################################################
# OpenVAS Vulnerability Test
#
# VMware products version detection (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800000");
  script_version("2019-05-20T11:12:48+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2008-09-25 10:10:31 +0200 (Thu, 25 Sep 2008)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VMWare products version detection (Windows)");

  script_tag(name:"summary", value:"This script retrieves all VMWare Products version from registry and saves
  those in KB.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
  key_list1 = make_list("SOFTWARE\VMware, Inc.\VMware GSX Server",
                        "SOFTWARE\VMware, Inc.\VMware Workstation",
                        "SOFTWARE\VMware, Inc.\VMware Player",
                        "SOFTWARE\VMWare, Inc.\VMWare Server",
                        "SOFTWARE\VMware, Inc.\VMware ACE");
}

else if("x64" >< os_arch){
  key_list  = make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
  key_list1 = make_list("SOFTWARE\Wow6432Node\VMware, Inc.\VMware GSX Server",
                        "SOFTWARE\Wow6432Node\VMware, Inc.\VMware Workstation",
                        "SOFTWARE\Wow6432Node\VMware, Inc.\VMware Player",
                        "SOFTWARE\Wow6432Node\VMWare, Inc.\VMWare Server",
                        "SOFTWARE\Wow6432Node\VMware, Inc.\VMware ACE");
}

if(isnull(key_list && key_list1)){
  exit(0);
}

if(registry_key_exists(key:"SOFTWARE\VMware, Inc.\VMware ACE\Dormant"))
{
  foreach vmkey (key_list)
  {
    foreach item (registry_enum_keys(key:vmkey))
    {
      vmace = registry_get_sz(key:vmkey + item, item:"DisplayName");
      if("VMware ACE Manager" >< vmace)
      {
        vmVer = registry_get_sz(key:vmkey + item, item:"DisplayVersion");
        break;
      }
    }
  }
}

##Flag to try to get build version
buildflag = 0;

if(!vmVer)
{
  foreach vmkey (key_list1)
  {
    vmVer = registry_get_sz(key:vmkey, item:"ProductVersion");
    vmPath = registry_get_sz(key:vmkey, item:"InstallPath");
    vmwareCode = registry_get_sz(key:vmkey, item:"ProductCode");

    if(vmVer && vmwareCode){
      buildflag = 1;
      break;
    }else
    if(!vmVer && vmwareCode)
    {
      uninstallkey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
      key = uninstallkey + vmwareCode;
      vmVer = registry_get_sz(key:key, item:"DisplayVersion");
      ##In some cases need to check both places for the product code
      if(!vmVer)
      {
        uninstallkey = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
        key = uninstallkey + vmwareCode;
        vmVer = registry_get_sz(key:key, item:"DisplayVersion");
      }
      if(!vmPath){
        vmPath = registry_get_sz(key:key, item:"InstallPath");
      }
      break;
    }

    ## Vmware workstation player 12.1.1 has vmVer but not vmwareCode
    ## Adding the below condition to avoid the iteration over the keys after fetching vmware player version
    else if(vmVer != NULL && vmPath != NULL)
    {
      buildflag = 1; ##build no is coming along with the version, i.e setting flag as 1
      break;
    }
  }
}

if(vmVer != NULL)
{
  vmware = split(vmVer, sep:".", keep:0);
  vmwareVer = vmware[0] + "." + vmware[1] + "." + vmware[2];
  if(buildflag != NULL)
  {
    vmwareBuild = vmware[3];
    if (vmwareBuild !~ "[0-9]+"){
      vmwareBuild = "";
    }
  }

  if(vmPath && !vmwareBuild)
  {
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:vmPath);
    file1 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                         string:vmPath + "vmware.exe");
    file2 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                         string:vmPath + "vmplayer.exe");
    file3 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                         string:vmPath + "vmware-authd.exe");

    name = kb_smb_name();
    if(!name) exit(0);

    port = kb_smb_transport();
    if(!port) exit(0);

    login  = kb_smb_login();
    pass   = kb_smb_password();
    domain = kb_smb_domain();

    soc = open_sock_tcp(port);
    if(!soc){
      exit(0);
    }

    r = smb_session_request(soc:soc, remote:name);
    if(!r){
      close(soc);
      exit(0);
    }

    prot = smb_neg_prot(soc:soc);
    if(!prot){
      close(soc);
      exit(0);
    }

    r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain,
                          prot:prot);
    if(!r){
      close(soc);
      exit(0);
    }

    uid = session_extract_uid(reply:r);
    if(!uid){
      close(soc);
      exit(0);
    }

    r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
    if(!r){
      close(soc);
      exit(0);
    }

    tid = tconx_extract_tid(reply:r);
    if(!tid){
      close(soc);
      exit(0);
    }

    fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file1);
    if(!fid)
    {
      fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file2);
      if(!fid)
      {
        fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file3);
        if(!fid)
        {
          close(soc);
          exit(0);
        }
      }
    }

    vmwareBuild = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, offset:290000,
                             verstr:"build-");
    close(soc);
  }

  if(vmwareBuild == "19175" && vmwareVer == "5.5.0"){
    vmwareVer = "5.5.1";
  }

  if(vmkey =~ "SOFTWARE\\VMWare, Inc."){
    product = ereg_replace(pattern:"SOFTWARE\\VMWare, Inc.\\VMWare (.*)",
                         string:vmkey, replace:"\1", icase:TRUE);
  } else if (vmkey =~ "SOFTWARE\\Wow6432Node\\VMware"){
    product = ereg_replace(pattern:"SOFTWARE\\Wow6432Node\\VMWare, Inc.\\VMWare (.*)",
                         string:vmkey, replace:"\1", icase:TRUE);
  }

  set_kb_item(name:"VMware/Win/Installed", value:TRUE);
  set_kb_item(name:"VMware/" + product + "/Win/Ver", value:vmwareVer);

  ##CPE based on product
  if("Player" >< product)
  {
    set_kb_item(name:"VMware/Player/Installed", value:TRUE);
    app = "VMware Player";
    tmpBase = "cpe:/a:vmware:player:" ;
  }else
  if("Server" >< product)
  {
    set_kb_item(name:"VMware/Server/Installed", value:TRUE);
    app = "VMware Server";
    tmpBase = "cpe:/a:vmware:server:";
  }else
  if("Workstation" >< product)
  {
    set_kb_item(name:"VMware/Workstation/Installed", value:TRUE);
    app = "VMware Workstation";
    tmpBase = "cpe:/a:vmware:workstation:";
  }else
  if("ACE" >< product)
  {
    set_kb_item(name:"VMware/ACE/Installed", value:TRUE);
    app = "VMware ACE";
    tmpBase = "cpe:/a:vmware:ace:";
  }
  register_and_report_cpe(app:app, ver:vmwareVer, base:tmpBase, expr:"^([0-9.]+([a-z0-9]+)?)",
                          insloc:vmPath);
  if(vmwareBuild){
    set_kb_item(name:"VMware/" + product + "/Win/Build", value:vmwareBuild);
  }
}
