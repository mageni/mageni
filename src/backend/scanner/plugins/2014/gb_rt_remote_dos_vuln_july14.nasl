###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rt_remote_dos_vuln_july14.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Request Tracker (RT) 'Email::Address::List' Remote Denial of Service Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:best_practical_solutions:request_tracker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804718");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-1474");
  script_bugtraq_id(68690);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-07-24 15:22:19 +0530 (Thu, 24 Jul 2014)");
  script_name("Request Tracker (RT) 'Email::Address::List' Remote Denial of Service Vulnerability");


  script_tag(name:"summary", value:"This host is installed with Request Tracker (RT) and is prone to remote
denial of service vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An algorithmic complexity flaw is in Perl CPAN Email::Address::List that is
triggered when handling a specially crafted string without an address.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to consume CPU resource resulting
in denial of service.");
  script_tag(name:"affected", value:"Request Tracker (RT) version 4.2.0 through 4.2.2");
  script_tag(name:"solution", value:"Upgrade to version 4.2.5 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://blog.bestpractical.com/2014/01/security-vulnerability-in-rt-42.html");
  script_xref(name:"URL", value:"http://lists.bestpractical.com/pipermail/rt-announce/2014-June/000257.html");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("rt_detect.nasl");
  script_mandatory_keys("RequestTracker/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://bestpractical.com/rt");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!RTVer = get_app_version(cpe:CPE, port:http_port)){
  exit(0);
}

if(version_in_range(version:RTVer, test_version:"4.2.0", test_version2:"4.2.2"))
{
  security_message(http_port);
  exit(0);
}
