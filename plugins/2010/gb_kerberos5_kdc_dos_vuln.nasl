###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kerberos5_kdc_dos_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# Kerberos5 KDC Cross Realm Referral Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.800441");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-01-22 09:23:45 +0100 (Fri, 22 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3295");
  script_bugtraq_id(37486);
  script_name("Kerberos5 KDC Cross Realm Referral Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://web.mit.edu/kerberos/advisories/2009-003-patch.txt");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37977");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3652");
  script_xref(name:"URL", value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2009-003.txt");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_kerberos5_detect.nasl");
  script_mandatory_keys("Kerberos5/Ver");
  script_tag(name:"affected", value:"kerberos5 version prior to 1.7.1");
  script_tag(name:"insight", value:"The flaw is caused by a NULL pointer dereference error in the KDC cross-realm
  referral processing implementation, which could allow an unauthenticated remote
  attacker to cause KDC to crash.");
  script_tag(name:"summary", value:"This host is installed with Kerberos5 and is prone to Denial of
  Service vulnerability.");
  script_tag(name:"solution", value:"Upgrade kerberos5 version 1.7.1

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of service.");
  script_xref(name:"URL", value:"http://web.mit.edu/kerberos/www/");
  exit(0);
}


include("version_func.inc");

krbVer = get_kb_item("Kerberos5/Ver");
if(!krbVer){
  exit(0);
}

if(version_is_less(version:krbVer, test_version:"1.7.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
