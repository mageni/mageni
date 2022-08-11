###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat NIO HTTP connector Information Disclosure Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811296");
  script_version("2019-05-10T11:41:35+0000");
  script_cve_id("CVE-2016-8745");
  script_bugtraq_id(94828);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2017-08-11 12:49:43 +0530 (Fri, 11 Aug 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Tomcat NIO HTTP connector Information Disclosure Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Apache Tomcat
  and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error handling of the
  send file code for the NIO HTTP connector in Apache Tomcat resulting in the
  current Processor object being added to the Processor cache multiple times.
  This in turn means that the same Processor could be used for concurrent requests.
  Sharing a Processor can result in information leakage between requests including,
  not not limited to, session ID and the response body.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Apache Tomcat versions 9.0.0.M1 to 9.0.0.M13,
  Apache Tomcat versions 8.5.0 to 8.5.8,
  Apache Tomcat versions 8.0.0.RC1 to 8.0.39,
  Apache Tomcat versions 7.0.0 to 7.0.73, and
  Apache Tomcat versions 6.0.16 to 6.0.48 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apache Tomcat version 9.0.0.M15
  or 8.5.9 or 8.0.41 or 7.0.75 or 6.0.50 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=60409");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.0.M15");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.41");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.75");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.9");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.50");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");
  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if(isnull(tomPort = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:tomPort, exit_no_version:TRUE))
  exit(0);

appVer = infos["version"];
path = infos["location"];

if(appVer =~ "^6\.")
{
  if((revcomp(a: appVer, b: "6.0.50") < 0) &&
     (revcomp(a: appVer, b: "6.0.16") >= 0)){
    fix = "6.0.50";
  }
}

else if(appVer =~ "^7\.")
{
  if(revcomp(a: appVer, b: "7.0.75") < 0){
    fix = "7.0.75";
  }
}

else if(appVer =~ "^8\.5\.")
{
  if(revcomp(a: appVer, b: "8.5.9") < 0){
    fix = "8.5.9";
  }
}

else if(appVer =~ "^8\.")
{
  if(revcomp(a: appVer, b: "8.0.41") < 0){
    fix = "8.0.41";
  }
}

else if(appVer =~ "^9\.")
{
  if(revcomp(a: appVer, b: "9.0.0.M15") < 0){
    fix = "9.0.0.M15";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix, install_path:path);
  security_message(data:report, port:tomPort);
  exit(0);
}
exit(0);
