###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_verydoc_pdf_viewer_activex_bof.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# VeryDOC PDF Viewer ActiveX Control Buffer Overflow Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800207");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-12-16 16:12:00 +0100 (Tue, 16 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5492");
  script_bugtraq_id(32313);
  script_name("VeryDOC PDF Viewer ActiveX Control Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/Advisories/32725");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7126");
  script_xref(name:"URL", value:"http://www.bmgsec.com.au/advisories/openpdf.txt");
  script_xref(name:"URL", value:"http://news.debuntu.org/content/9123-cve-2008-5492-verydoc_pdf_viewer");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application to cause heap based buffer overflow and can
  compromise a vulnerable system.");
  script_tag(name:"affected", value:"VeryDOC, PDF Viewer Pdfview.ocx version 2.0.0.1 and prior on Windows.");
  script_tag(name:"insight", value:"This flaw is due to boundary error in the OpenPDF function method from the
  PDFVIEW.PdfviewCtrl.1 ActiveX control (pdfview.ocx) which fails to properly
  validate the input data passed as large string.");
  script_tag(name:"summary", value:"This host is installed with VeryDOC PDF Viewer and is prone to
  Buffer Overflow vulnerability.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://verydoc.com/pdf-viewer-ocx.html");
  exit(0);
}


include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

# PDF Viewer ClSID Key
regKey = registry_key_exists(key:"SOFTWARE\Classes\CLSID\" +
                       "{433268D7-2CD4-43E6-AA24-2188672E7252}");
if(!regKey){
  exit(0);
}

# Workaround Check
clsid = "{433268D7-2CD4-43E6-AA24-2188672E7252}";
activeKey = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\" + clsid;
killBit = registry_get_dword(key:activeKey, item:"Compatibility Flags");

if(killBit && (int(killBit) == 1024)){
  exit(0);
}
else{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
