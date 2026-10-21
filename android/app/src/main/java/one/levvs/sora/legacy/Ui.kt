package one.levvs.sora.legacy

import android.app.Activity
import android.content.Context
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast

/** Small framework-View helpers: the whole UI is built in code, so
 *  there are no layout XML files and no view-binding/AAPT layout
 *  surface beyond strings and the theme. */
fun Activity.contentColumn(): LinearLayout {
    val column = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(16), dp(16), dp(16), dp(16))
    }
    setContentView(column)
    return column
}

fun Context.dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

fun LinearLayout.label(text: String, sizeSp: Float = 16f): TextView {
    val view = TextView(context).apply {
        this.text = text
        textSize = sizeSp
        setPadding(0, context.dp(6), 0, context.dp(6))
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
    params.topMargin = context.dp(6)
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
