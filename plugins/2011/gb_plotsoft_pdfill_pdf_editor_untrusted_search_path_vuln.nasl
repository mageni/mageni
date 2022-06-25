###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_plotsoft_pdfill_pdf_editor_untrusted_search_path_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# PlotSoft PDFill PDF Editor Untrusted Search Path Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802177");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_cve_id("CVE-2011-3690");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("PlotSoft PDFill PDF Editor Untrusted Search Path Vulnerability");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2011-3690");
  script_xref(name:"URL", value:"http://olex.openlogic.com/wazi/2011/pdfill-pdf-editor-8-0-medium/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_plotsoft_pdfill_pdf_editor_detect.nasl");
  script_mandatory_keys("PlotSoft/PDFill/PDF/Editor/Ver");
  script_tag(name:"insight", value:"The flaw is due to untrusted search path vulnerability, which
allows local users to gain privileges.");
  script_tag(name:"solution", value:"Upgrade to version 9.0 or later.");
  script_tag(name:"summary", value:"This host is installed with PlotSoft PDFill PDF Editor and is
prone to untrusted search path vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow local users to gain privileges
via a Trojan horse mfc70enu.dll or mfc80loc.dll in the current working directory.");
  script_tag(name:"affected", value:"PlotSoft PDFill PDF Editor version 8.0");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.pdfill.com/download.html");
  exit(0);
}


include("version_func.inc");

pdfVer = get_kb_item("PlotSoft/PDFill/PDF/Editor/Ver");
if(!pdfVer){
  exit(0);
}

if(version_is_equal(version:pdfVer, test_version:"8.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
