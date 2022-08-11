###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kerberos5_mult_int_underflow_vuln.nasl 14233 2019-03-16 13:32:43Z mmartin $
#
# Kerberos5 Multiple Integer Underflow Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
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
  script_oid("1.3.6.1.4.1.25623.1.0.800433");
  script_version("$Revision: 14233 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-16 14:32:43 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-01-20 08:21:11 +0100 (Wed, 20 Jan 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4212");
  script_name("Kerberos5 Multiple Integer Underflow Vulnerabilities");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=545015");
  script_xref(name:"URL", value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2009-004.txt");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_kerberos5_detect.nasl");
  script_mandatory_keys("Kerberos5/Ver");
  script_tag(name:"affected", value:"kerberos5 version 1.3 to 1.6.3, and 1.7");
  script_tag(name:"insight", value:"Multiple Integer Underflow due to errors within the 'AES' and 'RC4'
  decryption functionality in the crypto library in MIT Kerberos when
  processing ciphertext with a length that is too short to be valid.");
  script_tag(name:"summary", value:"This host is installed with Kerberos5 and is prone to multiple
  Integer Underflow vulnerability.");
  script_tag(name:"solution", value:"Apply the patch mentioned in the advisories below.

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of service
  or possibly execute arbitrary code.");
  script_xref(name:"URL", value:"http://web.mit.edu/kerberos/advisories/2009-004-patch_1.6.3.txt");
  script_xref(name:"URL", value:"http://web.mit.edu/kerberos/advisories/2009-004-patch_1.7.txt");
  exit(0);
}


include("version_func.inc");

krbVer = get_kb_item("Kerberos5/Ver");
if(!krbVer){
  exit(0);
}

if(version_is_equal(version:krbVer, test_version:"1.7") ||
   version_in_range(version:krbVer, test_version:"1.3", test_version2:"1.6.3")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
