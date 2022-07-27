###############################################################################
# OpenVAS Vulnerability Test
#
# tDiary 'tb-send.rb' Plugin Cross-Site Scripting Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.800992");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-0726");
  script_bugtraq_id(38413);
  script_name("tDiary 'tb-send.rb' Plugin Cross-Site Scripting Vulnerability");
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_tdiary_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tdiary/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"tDiary versions prior to 2.2.3.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of the 'plugin_tb_url' and
  'plugin_tb_excerpt' parameters upon submission to the tb-send.rb plugin script.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to version 2.2.3 or later.");

  script_tag(name:"summary", value:"The host is running tDiary and is prone to Cross-Site Scripting
  Vulnerability.");

  script_xref(name:"URL", value:"http://www.tdiary.org/20100225.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38742");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2010/JVNDB-2010-000005.html");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

diaryPort = get_http_port(default:80);

diaryVer = get_kb_item("www/" + diaryPort + "/tdiary");
if(isnull(diaryVer))
  exit(0);

diaryVer = eregmatch(pattern:"^(.+) under (/.*)$", string:diaryVer);
if(diaryVer[1] != NULL)
{
  if(version_is_less(version:diaryVer[1], test_version:"2.2.3")){
    security_message(diaryPort);
  }
}

