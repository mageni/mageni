# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_network_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118510");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2023-07-04 12:06:23 +0000 (Tue, 04 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_cve_id("CVE-2010-4008", "CVE-2010-4494", "CVE-2011-1202", "CVE-2011-1944",
                "CVE-2011-3970", "CVE-2012-0841", "CVE-2012-2870", "CVE-2012-2871",
                "CVE-2012-5134", "CVE-2012-6139", "CVE-2013-0338", "CVE-2013-0339",
                "CVE-2013-1969", "CVE-2013-2877", "CVE-2013-4520", "CVE-2014-3660",
                "CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499",
                "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-7995",
                "CVE-2015-8035", "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317",
                "CVE-2015-8710", "CVE-2015-8806", "CVE-2015-9019", "CVE-2016-1683",
                "CVE-2016-1684", "CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834",
                "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839",
                "CVE-2016-1840", "CVE-2016-2073", "CVE-2016-3189", "CVE-2016-3627",
                "CVE-2016-3705", "CVE-2016-3709", "CVE-2016-4447", "CVE-2016-4448",
                "CVE-2016-4449", "CVE-2016-4483", "CVE-2016-4607", "CVE-2016-4609",
                "CVE-2016-4658", "CVE-2016-5131", "CVE-2016-5180", "CVE-2016-9596",
                "CVE-2016-9597", "CVE-2016-9598", "CVE-2017-1000061", "CVE-2017-1000381",
                "CVE-2017-15412", "CVE-2017-16931", "CVE-2017-16932", "CVE-2017-18258",
                "CVE-2017-5029", "CVE-2017-5130", "CVE-2017-5969", "CVE-2017-7375",
                "CVE-2017-7376", "CVE-2017-8872", "CVE-2017-9047", "CVE-2017-9048",
                "CVE-2017-9049", "CVE-2017-9050", "CVE-2018-14404", "CVE-2018-14567",
                "CVE-2018-9251", "CVE-2019-11068", "CVE-2019-12900", "CVE-2019-13117",
                "CVE-2019-13118", "CVE-2019-16168", "CVE-2019-19242", "CVE-2019-19244",
                "CVE-2019-19317", "CVE-2019-19603", "CVE-2019-19645", "CVE-2019-19646",
                "CVE-2019-19880", "CVE-2019-19923", "CVE-2019-19924", "CVE-2019-19925",
                "CVE-2019-19926", "CVE-2019-19956", "CVE-2019-19959", "CVE-2019-20218",
                "CVE-2019-20388", "CVE-2019-20838", "CVE-2019-5815", "CVE-2019-8457",
                "CVE-2019-9936", "CVE-2019-9937", "CVE-2020-11655", "CVE-2020-11656",
                "CVE-2020-13434", "CVE-2020-13435", "CVE-2020-13630", "CVE-2020-13631",
                "CVE-2020-13632", "CVE-2020-13871", "CVE-2020-14155", "CVE-2020-15358",
                "CVE-2020-24977", "CVE-2020-35525", "CVE-2020-35527", "CVE-2020-7595",
                "CVE-2020-9327", "CVE-2021-20227", "CVE-2021-30560", "CVE-2021-31239",
                "CVE-2021-3517", "CVE-2021-3518", "CVE-2021-3537", "CVE-2021-3541",
                "CVE-2021-36690", "CVE-2021-3672", "CVE-2021-45346", "CVE-2022-22576",
                "CVE-2022-23308", "CVE-2022-23395", "CVE-2022-27774", "CVE-2022-27775",
                "CVE-2022-27776", "CVE-2022-27781", "CVE-2022-27782", "CVE-2022-29824",
                "CVE-2022-31160", "CVE-2022-32205", "CVE-2022-32206", "CVE-2022-32207",
                "CVE-2022-32208", "CVE-2022-32221", "CVE-2022-35252", "CVE-2022-35737",
                "CVE-2022-40303", "CVE-2022-40304", "CVE-2022-42915", "CVE-2022-42916",
                "CVE-2022-43551", "CVE-2022-43552", "CVE-2022-46908", "CVE-2022-4904",
                "CVE-2023-0465", "CVE-2023-0466", "CVE-2023-1255", "CVE-2023-23914",
                "CVE-2023-23915", "CVE-2023-23916", "CVE-2023-2650", "CVE-2023-27533",
                "CVE-2023-27534", "CVE-2023-27535", "CVE-2023-27536", "CVE-2023-27538",
                "CVE-2023-28320", "CVE-2023-28321", "CVE-2023-28322", "CVE-2023-28484",
                "CVE-2023-29469", "CVE-2023-31124", "CVE-2023-31130", "CVE-2023-31147",
                "CVE-2023-32067");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Network Monitor < 6.2.2 Multiple Vulnerabilities (TNS-2023-23)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nnm_smb_login_detect.nasl");
  script_mandatory_keys("tenable/nessus_network_monitor/detected");

  script_tag(name:"summary", value:"Tenable Nessus Network Monitor is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Several third-party components were found to contain
  vulnerabilities, and updated versions have been made available by the providers.");

  script_tag(name:"affected", value:"Tenable Nessus Network Monitor prior to version 6.2.2.");

  script_tag(name:"solution", value:"Update to version 6.2.2 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2023-23");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"6.2.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.2.2", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
