###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_smbv1_enabled.nasl 12511 2018-11-23 12:41:39Z cfischer $
#
# SMBv1 enabled (Remote Check)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140151");
  script_version("$Revision: 12511 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 13:41:39 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-02-04 09:33:13 +0100 (Sat, 04 Feb 2017)");
  script_name("SMBv1 enabled (Remote Check)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_smb_version_detect.nasl", "netbios_name_get.nasl",
                      "smb_nativelanman.nasl", "os_detection.nasl");
  script_mandatory_keys("smb_v1/supported", "Host/runs_windows");
  script_exclude_keys("SMB/samba");

  script_xref(name:"URL", value:"https://www.us-cert.gov/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2696547");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/204279");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS17-010");

  script_tag(name:"summary", value:"The remote Windows host is prone to an unspecified remote code execution vulnerability in SMBv1 protocol.

  This VT has been replaced by 'Microsoft Windows SMB Server Multiple Vulnerabilities-Remote (4013389)'
  (OID: 1.3.6.1.4.1.25623.1.0.810810).");

  script_tag(name:"insight", value:"The remote Windows host is supporting SMBv1 and is therefore prone to an unspecified remote code execution
  vulnerability. This vulnerability is related to the `Shadow Brokers` group.");

  script_tag(name:"solution", value:"Disable SMB v1 and/or block all versions of SMB at the network boundary by blocking TCP port 445 with related
  protocols on UDP ports 137-138 and TCP port 139, for all boundary devices.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);