package com.synonym.paykit

import android.content.Context

public object PaykitSdkDefaults {
    @JvmField
    public val DEFAULT_ENDPOINT_MANAGEMENT_SCOPE: EndpointManagementScope =
        EndpointManagementScope.MANAGED_ONLY

    @JvmField
    public val DEFAULT_ENCRYPTED_LINK_RECOVERY_MARKER_POLICY: EncryptedLinkRecoveryMarkerPolicy =
        EncryptedLinkRecoveryMarkerPolicy.ENABLED

    @JvmField
    public val DEFAULT_PUBLIC_CONTACT_SHARING_POLICY: PublicContactSharingPolicy =
        PublicContactSharingPolicy.LOCAL_ONLY
}

public object PaykitAndroid {
    init {
        System.loadLibrary("paykit")
    }

    /**
     * Initialize Android rustls-platform-verifier with an application Context.
     *
     * Still required for any remaining default rustls-platform-verifier
     * clients that need an application Context.
     *
     * ChatAuthFlow ICANN HTTP-relay polling and pkarr RelaysClient HTTPS both
     * use rustls + Mozilla/webpki roots on Android and do not consult this
     * verifier. PubkyTLS raw-public-key homeserver connections are unchanged.
     */
    @JvmStatic
    public fun initialize(context: Context): Boolean =
        nativeInitialize(context.applicationContext)

    /**
     * Same as [initialize], throwing if the platform verifier cannot be wired.
     */
    @JvmStatic
    public fun initializeOrThrow(context: Context) {
        check(initialize(context)) {
            "failed to initialize Paykit Android platform verifier"
        }
    }

    @JvmStatic
    private external fun nativeInitialize(context: Context): Boolean
}
