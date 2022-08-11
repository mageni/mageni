###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_investintech_prdts_detect.nasl 10884 2018-08-10 11:02:52Z cfischer $
#
# Investintech Products Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802501");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10884 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 13:02:52 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2011-11-09 17:25:24 +0530 (Wed, 09 Nov 2011)");
  script_name("Investintech Products Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script finds the installed version of Investintech
  products and sets the result in KB.");
  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  prdtName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Slim PDFReader
  if("SlimPDF Reader" >< prdtName)
  {
    pdfPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!isnull(pdfPath))
    {
      pdfVer = fetch_file_version(sysPath:pdfPath, file_name:"SlimPDF Reader.exe");
      if(pdfVer != NULL)
      {
        set_kb_item(name:"Investintech/Products/Installed", value:TRUE);
        set_kb_item(name:"SlimPDF/Reader/Ver", value:pdfVer);
        register_and_report_cpe(app:"SlimPDF Reader", ver:pdfVer, base:"cpe:/a:investintech:slimpdf_reader:",
                                expr:"^([0-9.]+)", insloc:pdfPath);
      }
    }
  }

  ## Able2Doc
  else if("Able2Doc" >< prdtName)
  {
    docVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(docVer != NULL)
    {
      set_kb_item(name:"Investintech/Products/Installed", value:TRUE);
      set_kb_item(name:"Able2Doc/Ver", value:docVer);

      register_and_report_cpe(app:"Able2Doc", ver:docVer, base:"cpe:/a:investintech:able2doc:",
                                expr:"^([0-9.]+)");
    }
  }

  ## Able2Doc Professional
  else if("Able2Doc Professional" >< prdtName)
  {
    docVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(docVer != NULL)
    {
      set_kb_item(name:"Investintech/Products/Installed", value:TRUE);
      set_kb_item(name:"Able2Doc/Pro/Ver", value:docVer);

      register_and_report_cpe(app:"Able2Doc Professional", ver:docVer, base:"cpe:/a:investintech:able2doc:::professional:",
                              expr:"^([0-9.]+)");
    }
  }

  ## Able2Extract
  else if(prdtName =~ "Able2Extract ([0-9.])+")
  {
    docVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(docVer != NULL)
    {
      set_kb_item(name:"Investintech/Products/Installed", value:TRUE);
      set_kb_item(name:"Able2Extract/Ver", value:docVer);

      register_and_report_cpe(app:"Able2Extract", ver:docVer, base:"cpe:/a:investintech:able2extract:",
                              expr:"^([0-9.]+)");
    }
  }

  else if("Able2Extract PDF Server" >< prdtName)
  {
    serVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(serVer != NULL)
    {
      set_kb_item(name:"Investintech/Products/Installed", value:TRUE);
      set_kb_item(name:"Able2Extract/PDF/Server/Ver", value:serVer);

      register_and_report_cpe(app:"Able2Extract PDF Server", ver:serVer, base:"cpe:/a:investintech:able2extract_server:",
                              expr:"^([0-9.]+)");
    }
  }
}
exit(0);
