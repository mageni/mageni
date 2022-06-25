###############################################################################
# OpenVAS Vulnerability Test
#
# phpBazar 'classified.php' SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.800465");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4221", "CVE-2009-4222");
  script_bugtraq_id(37144, 37132);
  script_name("phpBazar 'classified.php' SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54447");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/10245");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/0911-exploits/phpbazar211fix-sql.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_phpbazar_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpbazar/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary SQL commands in
  the affected application.");

  script_tag(name:"affected", value:"phpBazar version 2.1.1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to error in 'classified.php' which can be exploited to cause
  SQL injection via the 'catid' parameter, and 'admin/admin.php' which allows to
  obtain access to the admin control panel via a direct request.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running phpBazar and is prone to SQL Injection
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

pbport = get_http_port(default:80);

pbver = get_kb_item("www/" + pbport + "/phpBazar");
if(isnull(pbver))
  exit(0);

pbver = eregmatch(pattern:"^(.+) under (/.*)$", string:pbver);
if(!isnull(pbver[2]) && !safe_checks())
{
  url = string(pbver[2], "/classified.php?catid=2+and+1=0+union+all+select+1,2,3,4,5,6,7--");
  sndReq = http_get(item:url, port:pbport);
  rcvRes = http_send_recv(port:pbport, data:sndReq);

  if("2 and 1=0 union all select 1,2,3,4,5,6,7--&subcatid=1" >< rcvRes) {
    report = report_vuln_url(port:pbport, url:url);
    security_message(port:pbport, data:report);
    exit(0);
  } else {
    url = string(pbver[2], "/admin/admin.php");
    sndReq = http_get(item:url, port:pbport);
    rcvRes = http_send_recv(port:pbport, data:sndReq);
    if("phpBazar-AdminPanel" >< rcvRes) {
      report = report_vuln_url(port:pbport, url:url);
      security_message(port:pbport, data:report);
      exit(0);
    }
  }
}

if(!isnull(pbver[1]))
{
  # phpBazar version 2.1.1(2.1.0)
  if(version_is_less_equal(version:pbver[1], test_version:"2.1.0")){
    security_message(pbport);
  }
}
