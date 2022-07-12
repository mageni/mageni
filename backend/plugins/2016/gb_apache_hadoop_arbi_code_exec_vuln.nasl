###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_hadoop_arbi_code_exec_vuln.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# Apache Hadoop Arbitrary Command Execution Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:hadoop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810318");
  script_version("$Revision: 14181 $");
  script_cve_id("CVE-2016-5393");
  script_bugtraq_id(94574);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-12-23 15:26:24 +0530 (Fri, 23 Dec 2016)");
  script_name("Apache Hadoop Arbitrary Command Execution Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Apache Hadoop
  and is prone to an arbitrary command execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some unspecified error
  within the application allowing a remote user who can authenticate with the HDFS
  NameNode can possibly run arbitrary commands as the hdfs user.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to execute arbitrary commands on affected system.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"affected", value:"Apache Hadoop 2.6.x before 2.6.5
  and 2.7.x before 2.7.3");

  script_tag(name:"solution", value:"Upgrade to Apache Hadoop version 2.6.5
  or 2.7.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q4/537");
  script_xref(name:"URL", value:"http://mail-archives.apache.org/mod_mbox/hadoop-general/201611.mbox/%3CCAA0W1bTbUmUUSF1rjRpX-2DvWutcrPt7TJSWUcSLg1F0gyHG1Q%40mail.gmail.com%3E");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_hadoop_detect.nasl");
  script_mandatory_keys("Apache/Hadoop/Installed");
  script_require_ports("Services/www", 50070);

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!hadoopPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!hadoopVer = get_app_version(cpe:CPE, port:hadoopPort)){
  exit(0);
}

if(hadoopVer =~ "^(2\.(6|7))")
{
  if(version_in_range(version:hadoopVer, test_version:"2.6.0", test_version2:"2.6.4"))
  {
    fix = "2.6.5";
    VULN = TRUE;
  }

  else if(version_in_range(version:hadoopVer, test_version:"2.7.0", test_version2:"2.7.2"))
  {
    fix = "2.7.3";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:hadoopVer, fixed_version:fix);
    security_message(data:report, port:hadoopPort);
    exit(0);
  }
}
