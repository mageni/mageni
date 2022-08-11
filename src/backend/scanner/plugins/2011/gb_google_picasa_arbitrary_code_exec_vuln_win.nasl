###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_picasa_arbitrary_code_exec_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Google Picasa Insecure Library Loading Arbitrary Code Execution Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801770");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_cve_id("CVE-2011-0458");
  script_bugtraq_id(47031);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Google Picasa Insecure Library Loading Arbitrary Code Execution Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43853");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN99977321/index.html");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0766");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000022.html");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_picasa_detect_win.nasl");
  script_mandatory_keys("Google/Picasa/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code
  in the context of the user running the affected application.");
  script_tag(name:"affected", value:"Google Picasa versions prior to 3.8");
  script_tag(name:"insight", value:"The flaw is due to an error when loading executable and library files
  while using the 'Locate on Disk' feature.");
  script_tag(name:"solution", value:"Upgrade to the Google Picasa 3.8 or later.");
  script_tag(name:"summary", value:"The host is running Google Picasa and is prone to arbitrary code
  execution vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://picasa.google.com/thanks.html");
  exit(0);
}


include("version_func.inc");

picVer = get_kb_item("Google/Picasa/Win/Ver");
if(!picVer){
  exit(0);
}

if(version_is_less(version:picVer, test_version:"3.8")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
