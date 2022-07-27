###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_libre_office_lwp_mult_bof_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# LibreOffice LWP File Processing Multiple Buffer Overflow Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902399");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_cve_id("CVE-2011-2685");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("LibreOffice LWP File Processing Multiple Buffer Overflow Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44996/");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/953183");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_libreoffice_detect_portable_win.nasl");
  script_mandatory_keys("LibreOffice/Win/Ver");
  script_tag(name:"insight", value:"The flaws are due to errors in the import filter when processing Lotus
  Word Pro (LWP) files and can be exploited to cause a stack-based buffer
  overflow via a specially crafted file.");
  script_tag(name:"solution", value:"Upgrade to LibreOffice version 3.3.3 or 3.4.0 or later.");
  script_tag(name:"summary", value:"This host is installed with LibreOffice and is prone to multiple
  buffer overflow vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code.");
  script_tag(name:"affected", value:"LibreOffice version prior to 3.3.3");
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

if(version_is_less(version:officeVer, test_version:"3.3.301")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
