###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libre_office_doc_file_dos_vuln_win.nasl 11855 2018-10-12 07:34:51Z cfischer $
#
# LibreOffice 'DOC' File Denial of Service Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802557");
  script_version("$Revision: 11855 $");
  script_cve_id("CVE-2011-2713");
  script_bugtraq_id(49969);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 09:34:51 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-01-10 16:22:59 +0530 (Tue, 10 Jan 2012)");
  script_name("LibreOffice 'DOC' File Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2011/Oct/21");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?102615");
  script_xref(name:"URL", value:"http://www.libreoffice.org/advisories/CVE-2011-2713/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_libreoffice_detect_portable_win.nasl");
  script_mandatory_keys("LibreOffice/Win/Ver");
  script_tag(name:"insight", value:"The flaw is due to an error in 'OpenOffice.org'. A remote user can create
  a specially crafted Word document that, when loaded by the target user, will
  trigger an out-of-bounds read and potentially execute arbitrary code on the
  target system.");
  script_tag(name:"solution", value:"Upgrade to LibreOffice version 3.4.3 or later.");
  script_tag(name:"summary", value:"This host is installed with LibreOffice and is prone to denial of
  service vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  on the target system or cause denial of service.
  .");
  script_tag(name:"affected", value:"LibreOffice version 3.3.0 and 3.4.0 through 3.4.2");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.libreoffice.org/download/");
  exit(0);
}


include("version_func.inc");

officeVer = get_kb_item("LibreOffice/Win/Ver");
if(!officeVer){
  exit(0);
}

if(officeVer =~ "^3\..*")
{
  if(version_is_less(version:officeVer, test_version:"3.4.3"))
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
