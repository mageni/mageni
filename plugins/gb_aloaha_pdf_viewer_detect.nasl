###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aloaha_pdf_viewer_detect.nasl 2014-02-12 14:01:01Z feb$
#
# Aloaha PDF Suite PDF Viewer Version Detection (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804311");
  script_version("$Revision: 10898 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:38:13 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2014-02-12 20:03:19 +0530 (Wed, 12 Feb 2014)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Aloaha PDF Suite PDF Viewer Version Detection (Windows)");


  script_tag(name:"summary", value:"Detects the installed version of Aloaha PDF Suite PDF Viewer on Windows.

The script logs in via smb, searches for Aloaha PDF Suite in the registry
and gets the pdf viewer path from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

key = "SOFTWARE\Aloaha";
if(!registry_key_exists(key:key)){
  exit(0);
}

pdfPath = registry_get_sz(key:"SOFTWARE\Aloaha\pdf", item:"Path");
pdfPath = pdfPath + "\PDFViewer" ;

if(pdfPath)
{
  pdfVer = fetch_file_version(sysPath: pdfPath, file_name:"AloahaPDFViewer.exe");
  if(!pdfVer)
    exit(0);

  set_kb_item(name:"Aloaha/PDF/Viewer", value:pdfVer);

  cpe = build_cpe(value:pdfVer, exp:"^([0-9.]+)", base:"cpe:/a:aloha:aloahapdfviewer:");
  if(isnull(cpe))
    cpe = "cpe:/a:aloha:aloahapdfviewer";

  register_product(cpe: cpe, location: pdfPath);

  log_message(data: build_detection_report(app: "Aloaha PDF Viewer",
                                          version: pdfVer,
                                          install: pdfPath,
                                          cpe: cpe,
                                          concluded: pdfVer));
}
