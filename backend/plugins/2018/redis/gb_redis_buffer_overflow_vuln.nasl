###############################################################################
# OpenVAS Vulnerability Test
#
# Redis Buffer Overflow Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:redis:redis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813439");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-12326");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-06-18 16:33:41 +0530 (Mon, 18 Jun 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Redis Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"This host is running Redis and is prone to
  buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a buffer overflow
  error in redis-cli of Redis.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to achieve code execution and escalate to higher privileges via a crafted
  command line.");

  script_tag(name:"affected", value:"Redis versions before 4.0.10 and 5.x before
  5.0 RC3");

  script_tag(name:"solution", value:"Upgrade to Redis version 4.0.10 or 5.0 RC3
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://gist.github.com/fakhrizulkifli/f831f40ec6cde4f744c552503d8698f0");
  script_xref(name:"URL", value:"https://github.com/antirez/redis/commit/9fdcc15962f9ff4baebe6fdd947816f43f730d50");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/antirez/redis/4.0/00-RELEASENOTES");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/antirez/redis/5.0/00-RELEASENOTES");
  script_xref(name:"URL", value:"https://redis.io");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_redis_detect.nasl");
  script_require_ports("Services/redis", 6379);
  script_mandatory_keys("redis/installed");
  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE)) exit(0);
version = infos['version'];

if(version_is_less(version:version, test_version: "4.0.10")){
  fix = "4.0.10";
}

##5.0 RC1 == 4.9.101, 5.0 RC2 == 4.9.102
else if((version == "4.9.101") || (version == "4.9.102")){
  fix = "5.0 RC3";
}

if(fix)
{
  report = report_fixed_ver(installed_version:version, fixed_version: fix);
  security_message(port: port, data: report);
  exit(0);
}
exit(99);
