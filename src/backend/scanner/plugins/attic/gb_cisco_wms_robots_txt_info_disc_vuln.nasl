###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco WebEx Meetings Server 'robots.txt' Information Disclosure Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811043");
  script_version("2020-04-02T11:36:28+0000");
  script_cve_id("CVE-2017-6651");
  script_bugtraq_id(98387);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2017-05-16 13:24:42 +0530 (Tue, 16 May 2017)");
  script_name("Cisco WebEx Meetings Server 'robots.txt' Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is running Cisco WebEx Meetings
  Server and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an incomplete
  configuration of the 'robots.txt' file on customer-hosted WebEx solutions and
  occurs when the Short URL functionality is not activated.");

  script_tag(name:"impact", value:"Successfully exploiting this issue could allow
  the attacker to obtain scheduled meeting information and potentially allow the
  attacker to attend scheduled, customer meetings.");

  script_tag(name:"affected", value:"Cisco WebEx Meetings Server versions 2.5.x
  prior to 2.5MR6 Patch 6, 2.6.x prior to 2.6MR3 Security Patch 4, 2.7.x prior to
  2.7MR2 Security Patch 6, 2.8.x prior to 2.8 Security Patch 1");

  script_tag(name:"solution", value:"Upgrade to Cisco WebEx Meetings Server versions
  2.5MR6 Patch 6 or 2.6MR3 Security Patch 4 or 2.7MR2 Security Patch 6 or 2.8
  Security Patch 1 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve25950");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170510-cwms");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

# gb_cisco_webex_meetings_server_detect.nasl is currently only able to gather
# the major version like "2.7". The check for the minor version later can't work
# as expected.
exit(66);
