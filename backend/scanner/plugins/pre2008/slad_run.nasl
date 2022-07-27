###############################################################################
# OpenVAS Vulnerability Test
#
# Fetch results of SLAD queries from a remote machine
#
# Authors:
# Dirk Jagdmann
# Michael Wiegand
#
# Copyright:
# Copyright (c) 2005 Greenbone Networks GmbH
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.90002");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-24T11:20:30+0000");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2007-07-31 16:52:22 +0200 (Tue, 31 Jul 2007)");
  script_name("SLAD Run");
  script_tag(name:"cvss_base", value:"0.0");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("find_service.nasl", "ssh_authorization.nasl");
  script_mandatory_keys("login/SSH/success");
  script_require_ports(22, "Services/ssh");

  #  script_add_preference(name:"Execute Tripwire HIDS to check system's file integrity (Linux only)", type:"checkbox", value:"no");
  #  script_add_preference(name:"Execute ClamAV to search for virus-infected files (Linux only)", type:"checkbox", value:"no");
  #  script_add_preference(name:"ClamAV level", type:"radio", value:"Move infected files to quarantine;Remove infected files;Move infected files to quarantine exclude archives (.zip, .tgz, etc);Remove infected files exclude archives (.zip, .tgz, etc)");
  #  script_add_preference(name:"Execute LSOF to retrieve a list of open files (Linux only)", type:"checkbox", value:"no");
  #  script_add_preference(name:"Execute Tiger for various checks (Linux only)", type:"checkbox", value:"no");
  #  script_add_preference(name:"tiger level", type:"radio", value:"Checks user and passwd on local system;Check Filesystem Permissions;Check Systems Configuration and applications;Check running System and Processes;Perform all Tiger checks on system");
  #  script_add_preference(name:"Analyse Syslog-Files for security incidents (Linux only)", type:"checkbox", value:"no");
  #  script_add_preference(name:"syslogwatch level", type:"radio", value:"Analyse SysLogs low detail;Analyse SysLogs medium detail;Analyse SysLogs high detail");
  #  script_add_preference(name:"fetch hardware MB sensors (Linux only)", type:"checkbox", value:"no");
  #  script_add_preference(name:"Execute John-the-Ripper to find weak user passwords", type:"checkbox", value:"no");
  #  script_add_preference(name:"john level", type:"radio", value:"Fast-Crack;Dictionary Mode (slow);Full-Crack (very slow)");
  #  script_add_preference(name:"Execute ovaldi for scanning OVAL described issues", type:"checkbox", value:"no");
  #  script_add_preference(name:"ovaldi report format", type:"radio", value:"Text;HTML");
  #  script_add_preference(name:"Analyse SNMP-Traps collected by snmptrapd (Linux only)", type:"checkbox", value:"no");
  #  script_add_preference(name:"Fetch Snort-Events from the Snort MYSQL/MSSQL Database", type:"checkbox", value:"no");
  #  script_add_preference(name:"Execute ssh vulnkey to detect unsecure SSH RSA and DSA keys from broken Debian OpenSSL pkt (Linux only)", type:"checkbox", value:"no");
  #  script_add_preference(name:"Execute ChkRootKit to find installed rootkits (Linux only)", type:"checkbox", value:"no");
  #  script_add_preference(name:"Execute Netstat to Displays all connections and listening ports. (Windows only)", type:"checkbox", value:"no");
  #  script_add_preference(name:"netstat level", type:"radio", value:"udp/tcp and udpv6/tcpv6;tcp and tcpv6;udp and udpv6");
  #  script_add_preference(name:"Execute SFC to Scan integrity of all protected system files. This Function will only work on (Windows Vista/2008 and later)", type:"checkbox", value:"no");
  #  script_add_preference(name:"Execute Microsoft Baseline Security Analyzer (Windows only)", type:"checkbox", value:"no");
  #  script_add_preference(name:"MBSA level", type:"radio", value:"Run MBSA and check only for missing updates on Windows Update;Run MBSA and check only for missing updates on WSUS;Run MBSA and check only local Userpasswords;Run MBSA and check the OS;Run MBSA and check only InternetInformationServer;Run MBSA and check only SQL Server;Run MBSA and perform all Tests");

  script_tag(name:"summary", value:"This script connects to SLAD on a remote host to run
  remote scanners.

  To work properly, this script requires to be provided with a valid SSH login by means of an SSH key with pass-
  phrase if the SSH public key is passphrase-protected, or a password to log in.");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

exit(66);
