#
# Be sure to run `pod lib lint ETAxolotlKit.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'ETAxolotlKit'
  s.version          = '1.0.0'
  s.summary          = 'A short description of ETAxolotlKit.'

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

  s.description      = <<-DESC
  A short description of ETAxolotlKit.
                       DESC

  s.homepage         = 'https://github.com/feifu2023/ETAxolotlKit'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'ET0423WWW@163.com' => 'et0423www@163.com' }
  s.source           = { :git => 'https://github.com/feifu2023/ETAxolotlKit.git', :tag => s.version.to_s }

  s.ios.deployment_target = '12.0'
  s.frameworks = "Foundation","UIKit"
  s.swift_version = '5.0'
  
  s.source_files   = "ETAxolotlKit/**/*.{h,m,swift}"
  s.dependency 'ETCurve25519Kit'
  s.dependency 'HKDFKit'
  s.dependency 'SwiftProtobuf', '~> 1.21.0'

end
