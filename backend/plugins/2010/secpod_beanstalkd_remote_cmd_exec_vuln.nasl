###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_beanstalkd_remote_cmd_exec_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# Beanstalkd Job Data Remote Command Execution Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.901122");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-06-21 15:32:44 +0200 (Mon, 21 Jun 2010)");
  script_cve_id("CVE-2010-2060");
  script_bugtraq_id(40516);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Beanstalkd Job Data Remote Command Execution Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59107");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40032");
  script_xref(name:"URL", value:"http://github.com/kr/beanstalkd/commit/2e8e8c6387ecdf5923dfc4d7718d18eba1b0873d");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_beanstalkd_detect.nasl");
  script_mandatory_keys("Beanstalkd/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute Beanstalk
  client commands within the context of the affected application.");
  script_tag(name:"affected", value:"Beanstalkd version 1.4.5 and prior.");
  script_tag(name:"insight", value:"The flaw is caused by improper handling of put commands defining a job
  by the dispatch_cmd function. A remote attacker could exploit this
  vulnerability using a specially-crafted job payload data to execute
  arbitrary Beanstalk commands.");
  script_tag(name:"solution", value:"Upgrade to Beanstalkd version 1.4.6 or later.");
  script_tag(name:"summary", value:"This host is running Beanstalkd and is prone to remote command
  execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://kr.github.com/beanstalkd/download.html");
  exit(0);
}


include("version_func.inc");

ver = get_kb_item("Beanstalkd/Ver");
if(!ver){
  exit(0);
}

if(version_is_less(version:ver, test_version:"1.4.6")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
