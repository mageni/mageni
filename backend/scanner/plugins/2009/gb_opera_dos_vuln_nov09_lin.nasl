###############################################################################
# OpenVAS Vulnerability Test
#
# Opera Denial Of Service Vulnerability - Nov09 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801141");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-11-04 07:03:36 +0100 (Wed, 04 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3831");
  script_bugtraq_id(36850);
  script_name("Opera Denial Of Service Vulnerability - Nov09 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37182");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/938/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unix/1001/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3073");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Successful attackers may leads to Denial of Service on the affected application.");
  script_tag(name:"affected", value:"Opera version prior to 10.01 on Linux.");
  script_tag(name:"insight", value:"An error when processing domain names can be exploited to cause a memory
  corruption.");
  script_tag(name:"solution", value:"Upgrade to Opera version 10.01 or later.");
  script_tag(name:"summary", value:"This host is installed with Opera Web Browser and is prone to
  Denial of Service vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer)
  exit(0);

if(version_is_less(version:operaVer, test_version:"10.01")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
