##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pgp_desktop_data_spoofing_vuln.nasl 12694 2018-12-06 15:28:57Z cfischer $
#
# PGP Desktop Signed Data Spoofing Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801552");
  script_version("$Revision: 12694 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-06 16:28:57 +0100 (Thu, 06 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-12-09 06:49:11 +0100 (Thu, 09 Dec 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-3618");
  script_name("PGP Desktop Signed Data Spoofing Vulnerability");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_pgp_desktop_detect_win.nasl");
  script_mandatory_keys("PGPDesktop/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to spoof signed
data by concatenating an additional message to the end of a legitimately
signed message.");
  script_tag(name:"affected", value:"PGP Desktop version 10.0.x to 10.0.3 and 10.1.0");
  script_tag(name:"insight", value:"This flaw is caused by an error when verifying encrypted
or signed data, which could allow attackers to insert unsigned packets
or encrypted data into an OpenPGP message containing signed and/or
encrypted data.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to version 10.0.3 SP2, 10.1.0 SP1 or higher.");
  script_tag(name:"summary", value:"This host is running PGP Desktop and is prone to signed data
spoofing Vulnerability");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/300785");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3026");
  script_xref(name:"URL", value:"https://pgp.custhelp.com/app/answers/detail/a_id/2290");
  script_xref(name:"URL", value:"http://www.symantec.com/business/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2010&suid=20101118_00");

  script_xref(name:"URL", value:"http://www.pgp.com/products/desktop/index.html");
  exit(0);
}


include("version_func.inc");

ver = get_kb_item("PGPDesktop/Win/Ver");
if(!ver){
  exit(0);
}

if(version_is_equal(version:ver, test_version:"10.1.0") ||
   version_in_range(version:ver, test_version:"10.0.0", test_version2:"10.0.3.1")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}
