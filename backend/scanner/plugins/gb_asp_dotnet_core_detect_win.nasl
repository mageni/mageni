####################################################################################
# OpenVAS Vulnerability Test
#
# ASP.NET Core/.NET Core SDK Detection (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
####################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812949");
  script_version("2019-05-20T11:12:48+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2018-02-26 16:34:26 +0530 (Mon, 26 Feb 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ASP.NET Core/.NET Core SDK Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  ASP.NET Core.

  The script logs in via smb, searches for 'Microsoft .NET Core in the registry
  and gets the version from 'DisplayName' string from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
  key_list1 = make_list("SOFTWARE\Microsoft\ASP.NET Core\");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
  key_list1 = make_list("SOFTWARE\Microsoft\ASP.NET Core\",
                        "SOFTWARE\Wow6432Node\Microsoft\ASP.NET Core\");
}

##ASP .NET Core
foreach key (key_list1)
{
  key = key + "Runtime Package Store";
  foreach item (registry_enum_keys(key:key))
  {
    version = eregmatch(pattern:"v([0-9.]+)", string:item);
    coreVer = version[1];

    if(coreVer && coreVer !~ "[0-9]+\.[0-9]+\.[0-9]+")
    {
      foreach key (key_list)
      {
        foreach item (registry_enum_keys(key:key))
        {
          psName = registry_get_sz(key:key + item, item:"DisplayName");
          if("Microsoft ASP .NET Core" >< psName|| "Microsoft ASP.NET Core" >< psName)
          {
            version = eregmatch(pattern:"Microsoft ASP( )?.NET Core ([0-9.]+) ", string:psName);
            if(version[2]){
              coreVer = version[2];
              break;
            }
          }
        }
      }
    }

    if(coreVer)
    {
      set_kb_item(name:"ASP.NET/Core/Ver", value:coreVer);
      aspflag = TRUE;
      cpe = build_cpe(value:coreVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:asp.net_core:");
      if(!cpe)
        cpe = "cpe:/a:microsoft:asp.net_core";

      if("64" >< os_arch && "Wow6432Node" >!< key)
      {
        set_kb_item(name:"ASP.NET64/Core/Ver", value:coreVer);
        cpe = build_cpe(value:coreVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:asp.net_core:x64:");
        if(!cpe)
          cpe = "cpe:/a:microsoft:asp.net_core:x64";
      }
      register_and_report_cpe(app:"ASP .NET Core", ver:coreVer, concluded: "ASP .NET Core " + coreVer,
                              cpename:cpe, insloc:"Couldn find the install location from registry");
      break;
    }
  }
}

if(!aspflag)
{
  ##ASP .NET Core
  foreach key (key_list)
  {
    foreach item (registry_enum_keys(key:key))
    {
      psName = registry_get_sz(key:key + item, item:"DisplayName");
      if(psName =~ "Microsoft (ASP)?.NET Core")
      {
        aspcoreVer = eregmatch(pattern:"Microsoft (ASP)?.NET Core ([0-9.]+)", string:psName);
        if(aspcoreVer[2])
        {
          coreVer = aspcoreVer[2] ;
          set_kb_item(name:"ASP.NET/Core/Ver", value:coreVer);
          cpe = build_cpe(value:coreVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:asp.net_core:");
          if(!cpe)
            cpe = "cpe:/a:microsoft:asp.net_core";

          if("64" >< os_arch && "Wow6432Node" >!< key)
          {
            set_kb_item(name:"ASP.NET64/Core/Ver", value:coreVer);
            cpe = build_cpe(value:coreVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:asp.net_core:x64:");
            if(!cpe)
              cpe = "cpe:/a:microsoft:asp.net_core:x64";
          }
          register_and_report_cpe(app:"ASP .NET Core", ver:coreVer, concluded: "ASP .NET Core " + coreVer,
                              cpename:cpe, insloc:"Couldn find the install location from registry");
          break;
        }
      }
    }
  }
}

##.NET Core SDK
foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    psName = registry_get_sz(key:key + item, item:"DisplayName");
    if(psName =~ "(Microsoft )?.NET Core SDK")
    {
      sdkVer = eregmatch(pattern:"Microsoft .NET Core SDK - ([0-9.]+)", string:psName);
      sdkVer = sdkVer[1];
      if(!sdkVer)
      {
        sdkVer = eregmatch(pattern:"(Microsoft )?.NET Core SDK ([0-9.]+)", string:psName);
        sdkVer = sdkVer[2];
      }
      if(sdkVer)
      {
        set_kb_item(name:".NET/Core/SDK/Ver", value:sdkVer);

        cpe = build_cpe(value:sdkVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:.netcore_sdk:");
        if(!cpe)
          cpe = "cpe:/a:microsoft:.netcore_sdk:";

        if("64" >< os_arch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:".NET64/Core/SDK/Ver", value:sdkVer);
          cpe = build_cpe(value:sdkVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:.netcore_sdk:x64:");
          if(!cpe)
            cpe = "cpe:/a:microsoft:.netcore_sdk:x64";
        }
        register_and_report_cpe(app:".NET Core SDK", ver:sdkVer, concluded: ".NET Core SDK " + sdkVer,
                              cpename:cpe, insloc:"Couldn find the install location from registry");
        continue;
      }
    }

    if(psName =~ "Microsoft .NET Core.*Runtime")
    {
      runVer = eregmatch(pattern:"Microsoft .NET Core Runtime - ([0-9.]+)", string:psName);
      if(!runVer){
        runVer = eregmatch(pattern:"Microsoft .NET Core ([0-9.]+) - Runtime", string:psName);
      }
      if(runVer)
      {
        set_kb_item(name:".NET/Core/Runtime/Ver", value:runVer[1]);
        if("64" >< os_arch && "Wow6432Node" >!< key){
          set_kb_item(name:".NET64/Core/Runtime/Ver", value:runVer[1]);
        }
      }
    }
  }
}
