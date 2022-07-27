###############################################################################
# OpenVAS Vulnerability Test
#
# Multiple Buffer Overflow Vulnerabilities in Free Download Manager
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
  script_oid("1.3.6.1.4.1.25623.1.0.800349");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0183", "CVE-2009-0184");
  script_bugtraq_id(33554, 33555);
  script_name("Multiple Buffer Overflow Vulnerabilities in Free Download Manager");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33524");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2009-3/");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2009-5/");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/33555-SkD.pl");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_free_download_mang_detect.nasl");
  script_mandatory_keys("FreeDownloadManager/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code and can cause denial-of-service in the affected application.");
  script_tag(name:"affected", value:"Free Download Manager version prior to 3.0 build 848 on Windows.");
  script_tag(name:"insight", value:"Multiple buffer overflow errors due to,

  - a long file name within a torrent file.

  - a long tracker URL in a torrent file.

  - a long comment in a torrent file.

  - a long Authorization header in an HTTP request.");
  script_tag(name:"solution", value:"Upgrade to version 3.0 build 848.");
  script_tag(name:"summary", value:"This host has installed Free Download Manager and is prone to
  multiple buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

fdmVer = get_kb_item("FreeDownloadManager/Ver");
if(!fdmVer)
  exit(0);

if(version_is_less(version:fdmVer, test_version:"3.0.848.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
