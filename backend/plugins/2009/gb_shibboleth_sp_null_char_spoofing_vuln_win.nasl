###############################################################################
# OpenVAS Vulnerability Test
#
# Shibboleth Service Provider NULL Character Spoofing Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801116");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-10-15 15:35:39 +0200 (Thu, 15 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3475");
  script_name("Shibboleth Service Provider NULL Character Spoofing Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36861/");
  script_xref(name:"URL", value:"http://shibboleth.internet2.edu/secadv/secadv_20090817.txt");

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_shibboleth_sp_detect_win.nasl");
  script_mandatory_keys("Shibboleth/SP/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow man-in-the-middle attackers to spoof
  arbitrary SSL servers via a crafted certificate by a legitimate
  Certification Authority.");
  script_tag(name:"affected", value:"Shibboleth Service Provider version 1.3.x before 1.3.3 and 2.x before 2.2.1
  on Windows.");
  script_tag(name:"insight", value:"The flaw exists when using PKIX trust validation. The application does not
  properly handle a '\0' character in the subject or subjectAltName fields
  of a certificate.");
  script_tag(name:"solution", value:"Upgrade Shibboleth Service Provider version 1.3.3 or 2.2.1 or later.");
  script_tag(name:"summary", value:"The host has Shibboleth Service Provider installed and is prone to
  NULL Character Spoofing vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

shibVer = get_kb_item("Shibboleth/SP/Win/Ver");
if(!shibVer)
  exit(0);

if(version_in_range(version:shibVer, test_version:"1.3", test_version2:"1.3.2")||
   version_in_range(version:shibVer, test_version:"2.0", test_version2:"2.2.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
