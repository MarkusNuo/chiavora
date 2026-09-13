const { withAppBuildGradle, withProjectBuildGradle } = require('expo/config-plugins');

/** Pinned here, or Expo pins its own NDK and build tools and Gradle tries to download them. */
module.exports = function withChiavoraAndroid(config, options) {
  const ext = options && options.ext;
  if (!ext || Object.keys(ext).length === 0) {
    throw new Error('with-chiavora-android needs an `ext` object of Gradle properties to pin');
  }

  const withExt = withProjectBuildGradle(config, (modConfig) => {
    if (modConfig.modResults.language !== 'groovy') {
      throw new Error(
        `with-chiavora-android expected a Groovy build.gradle, got ${modConfig.modResults.language}`,
      );
    }

    const anchor = 'apply plugin: "expo-root-project"';
    if (!modConfig.modResults.contents.includes(anchor)) {
      throw new Error(
        `with-chiavora-android could not find ${anchor} in the generated build.gradle`,
      );
    }

    const assignments = Object.entries(ext).map(([key, value]) => `ext.${key} = "${value}"`);

    // Before the plugin applies, which sets each version only if it is not already set.
    modConfig.modResults.contents = modConfig.modResults.contents.replace(
      anchor,
      [
        '// Set by apps/mobile/plugins/with-chiavora-android.js — the SDK',
        "// components verified against Google's manifest and 049.",
        '// Expo would otherwise pin its own and try to download them.',
        ...assignments,
        '',
        anchor,
      ].join('\n'),
    );

    return modConfig;
  });

  return withBundledDebugJs(withExt);
};

/** The debug variant embeds its JS bundle, so a measurement run needs no Metro server. */
function withBundledDebugJs(config) {
  return withAppBuildGradle(config, (modConfig) => {
    const anchor = '    /* Variants */';
    if (!modConfig.modResults.contents.includes(anchor)) {
      throw new Error(
        'with-chiavora-android could not find the react { } variants block in app/build.gradle',
      );
    }
    modConfig.modResults.contents = modConfig.modResults.contents.replace(
      anchor,
      [
        '    // Set by apps/mobile/plugins/with-chiavora-android.js: the debug',
        '    // APK embeds its JS bundle instead of fetching it from Metro, so a',
        '    // measurement run needs no dev server. See the plugin for why.',
        '    debuggableVariants = []',
        '',
        anchor,
      ].join('\n'),
    );
    return modConfig;
  });
}
