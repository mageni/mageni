###############################################################################
# OpenVAS Vulnerability Test
#
# Snitz Forums 2000 'members.asp' SQL Injection and Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802243");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)");
  script_bugtraq_id(45381);
  script_cve_id("CVE-2010-4826", "CVE-2010-4827");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Snitz Forums 2000 'members.asp' SQL Injection and Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42308");
  script_xref(name:"URL", value:"http://forum.snitz.com/forum/topic.asp?TOPIC_ID=69770");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("snitz_forums_2000_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("snitzforums/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to steal cookie-based
  authentication credentials, compromise the application, access or modify
  data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Snitz Forums 2000 version 3.4.07.");

  script_tag(name:"insight", value:"- Input passed to the 'M_NAME' parameter in members.asp is not properly
  sanitised before being returned to the user. This can be exploited to
  execute arbitrary HTML and script code in a user's browser session in
  context of an affected site.

  - Input passed to the 'M_NAME' parameter in members.asp is not properly
  sanitised before being used in SQL queries. This can be exploited to
  manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"summary", value:"The host is running Snitz and is prone to SQL injection and cross
  site scripting vulnerabilities.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://forum.snitz.com/forum/topic.asp?TOPIC_ID=69770");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

ver = get_version_from_kb(port:port, app:"SnitzForums");
if(ver)
{
  if(version_is_equal(version:ver, test_version:"3.4.07")){
    security_message(port);
  }
}
