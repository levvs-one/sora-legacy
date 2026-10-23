package one.levvs.sora.legacy

import android.app.Activity
import android.content.Context
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

/** Small framework-View helpers: the whole UI is built in code, so
 *  there are no layout XML files and no view-binding/AAPT layout
 *  surface beyond strings and the theme.
 *
 *  One spacing scale for the whole client: padding and margins are
 *  8 or 16 dp, nothing in between; text sizes use the framework
 *  steps 12 / 14 / 16 / 20 / 24 sp at the call sites. */
private fun Activity.newColumn(): LinearLayout =
    LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(16), dp(16), dp(16), dp(16))
    }

fun Activity.contentColumn(): LinearLayout {
    val column = newColumn()
    setContentView(column)
    return column
}

/** Same column inside a ScrollView: screens whose content height is
 *  not bounded by a flexible child (status + log, settings + engine
 *  summary) must stay reachable on short viewports — landscape,
 *  split-screen, large font scale — instead of clipping the tail. */
fun Activity.scrollableContentColumn(): LinearLayout {
    val column = newColumn()
    val scroll = ScrollView(this).apply {
        addView(column, ViewGroup.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    }
    setContentView(scroll)
    return column
}

fun Context.dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

fun LinearLayout.label(text: String, sizeSp: Float = 16f): TextView {
    val view = TextView(context).apply {
        this.text = text
        textSize = sizeSp
        setPadding(0, context.dp(8), 0, context.dp(8))
    }
    addView(view, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    return view
}

fun LinearLayout.button(text: String, onClick: (View) -> Unit): Button {
    val view = Button(context).apply {
        this.text = text
        setOnClickListener(onClick)
    }
    val params = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
    params.topMargin = context.dp(8)
    addView(view, params)
    return view
}

fun LinearLayout.input(hint: String, multiLine: Boolean = false, number: Boolean = false): EditText {
    val view = EditText(context).apply {
        this.hint = hint
        if (multiLine) {
            minLines = 4
            maxLines = 10
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE
        }
        if (number) inputType = android.text.InputType.TYPE_CLASS_NUMBER
    }
    addView(view, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    return view
}

fun Activity.toast(message: String) {
    Toast.makeText(this, message, Toast.LENGTH_LONG).show()
}
