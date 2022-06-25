###############################################################################
# OpenVAS Vulnerability Test
#
# MS Internet Explorer 'VBScript' Remote Code Execution Vulnerability (981169)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800482");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0483");
  script_bugtraq_id(38463);
  script_name("MS Internet Explorer 'VBScript' Remote Code Execution Vulnerability");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  via specially crafted attack.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 6.x, 7.x, 8.x");

  script_tag(name:"insight", value:"The flaw exists in the way that 'VBScript' interacts with Windows Help files
  when using Internet Explorer. If a malicious Web site displayed a specially
  crafted dialog box and a user pressed the F1 key, it allows arbitrary code
  to be executed in the security context of the currently logged-on user.");

  script_tag(name:"summary", value:"The host is installed with Internet Explorer and VBScript and is
  prone to Remote Code Execution vulnerability.");

  script_tag(name:"solution", value:"Apply the latest updates. Please see the references for more information.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2010/981169");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); ## Plugin may results to FP
